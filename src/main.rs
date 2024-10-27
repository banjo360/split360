use byteorder::WriteBytesExt;
use std::io::BufRead;
use std::io::BufReader;
use std::io::SeekFrom;
use std::fs::OpenOptions;
use std::fs::File;
use serde::Deserialize;
use std::io;
use std::io::Seek;
use std::io::Read;
use std::io::Write;
use std::env;
use std::collections::HashMap;
use byteorder::{ReadBytesExt, LittleEndian};

use capstone::prelude::*;
use sha1::{Sha1, Digest};

#[derive(Debug, PartialEq, Deserialize)]
struct Segment {
    start: u64,
    size: usize,
    name: String,
    path: Option<String>,
    format: String,
    segment: Option<String>,
}

#[derive(Debug, PartialEq, Deserialize)]
struct Splitter {
    name: String,
    sha1: String,
    segments: Vec<Segment>,
}

fn main() {
    let mut args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        panic!("Not enough args");
    }

    let cmd = args[1].clone();
    args.drain(0..2);

    match cmd.as_str() {
        "split" => cmd_split(args),
        "merge" => cmd_merge(args),
        "checksum" => cmd_checksum(args),
        _ => panic!("Unknown command '{}'.", cmd)
    };
}

fn cmd_split(args: Vec<String>) {
    if args.len() < 1 || args.len() > 2 {
        panic!("'split' command requires 1 argument and 2 optional ones: <file>.yaml [<file>.xex]");
    }

    let mut symbols = HashMap::<String, u64>::new();

    if std::fs::metadata("addresses.txt").is_ok() {
        for line in std::fs::read_to_string("addresses.txt").unwrap().lines() {
            let linedata: Vec<_> = line.split(" ").collect();
            assert_eq!(linedata.len(), 2);
            
            let addr = u64::from_str_radix(&linedata[0][2..], 16).unwrap();
            let name = linedata[1].to_string();

            symbols.insert(name, addr);
        }
    }

    let strbuf = std::fs::read_to_string(args[0].clone()).unwrap();
    let result: Splitter = serde_yaml::from_str(&strbuf).unwrap();
    let input_file = if args.len() > 1 { args[1].clone() } else { "default.xex".to_string() };

    if !check_sha1sum(&input_file, &result.sha1) {
        panic!("{} doesn't have the correct sha1.", input_file);
    }

    let mut curr_addr = 0u64;
    let file_size = std::fs::metadata(&input_file).unwrap().len();
    let mut f = File::open(&input_file).unwrap();
    let mut index = 0;
    while curr_addr < file_size/*index < result.segments.len()*/ {
        let start = if index < result.segments.len() { result.segments[index].start } else { file_size };

        if curr_addr < start {
            std::fs::create_dir_all("bin").unwrap();

            let size = (start - curr_addr) as usize;
            let filename = format!("bin/bin_{:x}.bin", curr_addr);

            dump_bin(&mut f, size, &filename);

            curr_addr = start;
        } else if curr_addr == start {
            let seg = &result.segments[index];
            let size = seg.size;

            assert_eq!(f.stream_position().unwrap(), curr_addr);
            let mut buff = vec![0u8; size as usize];
            f.read(&mut buff).unwrap();

            match seg.format.as_str() {
                "bin" => {
                    let dir = if let Some(path) = &seg.path { &path } else { "bin" };
                    std::fs::create_dir_all(dir).unwrap();
                    std::fs::write(format!("{}/{}.bin", dir, seg.name), buff).unwrap();
                },
                "asm" => disassemble(&seg, &buff, &symbols, "asm"),
                "c" => {
                    if seg.segment.is_none() {
                        disassemble(&seg, &buff, &symbols, "matching");
                    }
                },
                "obj" => {
                    let dir = "matching";
                    std::fs::create_dir_all(dir).unwrap();
                    std::fs::write(format!("{}/{}.bin", dir, seg.name), buff).unwrap();
                },
                _ => panic!("Unknown format '{}'!", seg.format),
            };

            curr_addr += seg.size as u64;
            index += 1;
        } else {
            panic!("Expected address ({:#X}) is lower than current address ({:#X}). Check your .yaml file.", start, curr_addr);
        }
    }
}

fn dump_bin(file: &mut File, size: usize, filename: &str) {
    let mut buff = vec![0u8; size];
    file.read(&mut buff).unwrap();
    std::fs::write(filename, buff).unwrap();
}

fn disassemble(segment: &Segment, data: &[u8], symbols: &HashMap::<String, u64>, directory: &str) {
    std::fs::create_dir_all(directory).unwrap();
    std::fs::write(format!("{}/{}.bin", directory, segment.name), data).unwrap();
    
    let vram = if symbols.contains_key(&segment.name) { symbols[&segment.name] } else { 0 };

    let cs = Capstone::new()
        .ppc()
        .mode(arch::ppc::ArchMode::Mode32)
        .endian(capstone::Endian::Big)
        .build()
        .expect("Failed to create Capstone object");
    let insns = cs.disasm_all(data, vram).expect("Failed to disassemble");

    let mut f = File::create(format!("{}/{}.s", directory, segment.name)).expect("Unable to create file");
    write!(f, "{}:\n", segment.name).unwrap();
    for i in insns.as_ref() {
        write!(f, "{}\n", i).unwrap();
    }
}

fn calculate_sha1sum(filename: &str) -> String {
    let content = std::fs::read(&filename).unwrap();
    let sha1sum = Sha1::digest(&content);
    hex::encode(&sha1sum)
}

fn check_sha1sum(filename: &str, sha1: &str) -> bool {
    sha1 == calculate_sha1sum(filename)
}

fn cmd_merge(args: Vec<String>) {
    if args.len() != 2 {
        panic!("'merge' command requires 2 arguments: <file>.yaml <file>.xex");
    }

    let strbuf = std::fs::read_to_string(args[0].clone()).unwrap();
    let result: Splitter = serde_yaml::from_str(&strbuf).unwrap();
    let output_filename = args[1].clone();

    let mut output_file = OpenOptions::new().write(true).create(true).open(&output_filename).unwrap();

    let mut curr_addr = 0;
    let mut index = 0;
    while index < result.segments.len() {
        let seg = &result.segments[index];

        let filename = if seg.start == curr_addr {
            let n = &seg.name;
            let f = &seg.format;
            curr_addr += seg.size as u64;
            index += 1;
            let segment_type = if let Some(seg_name) = &seg.segment {
                format!(".{}", seg_name)
            } else {
                "".to_string()
            };

            let binfile = match f.as_str() {
                "bin" => {
                    let dir = if let Some(path) = &seg.path { &path } else { "bin" };
                    format!("{dir}/{n}.bin")
                },
                "c" => format!("build/{n}{segment_type}.bin"),
                "asm" => format!("asm/{n}.bin"),
                "obj" => merge_obj_file(&n).unwrap(),
                _ => panic!("Unknown format '{f}'.")
            };

            let file_size = std::fs::metadata(&binfile).unwrap().len();
            if file_size != seg.size as u64 {
                panic!("{binfile} is {} bytes when it should be {}.", file_size, seg.size);
            }
            binfile
        } else {
            let tmp_addr = curr_addr;
            curr_addr = seg.start;
            let file_size = std::fs::metadata(&format!("bin/bin_{:x}.bin", tmp_addr)).expect(&format!("bin/bin_{:x}.bin does not exist", tmp_addr)).len();
            assert_eq!(file_size, curr_addr - tmp_addr);
            format!("bin/bin_{:x}.bin", tmp_addr)
        };

        let mut other_file = OpenOptions::new().read(true).open(&filename).unwrap();
        io::copy(&mut other_file, &mut output_file).unwrap();
    }

    let last_filename = format!("bin/bin_{:x}.bin", curr_addr);
    if std::fs::metadata(&last_filename).is_ok() {
        let mut other_file = OpenOptions::new().read(true).open(&last_filename).unwrap();
        io::copy(&mut other_file, &mut output_file).unwrap();
    }
}

fn merge_obj_file(filename: &str) -> std::io::Result<String> {
    let mut f = File::open(format!("build/{filename}.obj"))?;
    let format = f.read_u16::<LittleEndian>()?;
    assert_eq!(format, 0x01f2);
    let sections_count = f.read_u16::<LittleEndian>()?;
    f.seek(SeekFrom::Current(0x04))?;
    let symbols_table = f.read_u32::<LittleEndian>()?;
    let symbols_count = f.read_u32::<LittleEndian>()?;
    let strings_table = symbols_table + 18 * symbols_count;
    f.seek(SeekFrom::Current(0x04))?;

    let mut functions_names = vec![];

    for section_id in 1..=sections_count {
        let mut buff = vec![0; 8usize];
        f.read(&mut buff).unwrap();
        let name = String::from_utf8(buff).unwrap().trim_matches(char::from(0)).to_string();
        f.seek(SeekFrom::Current(0x20))?;

        if name == ".text" {
            let pos = f.stream_position()?;

            let mut current = None;

            for id in 0..symbols_count {
                f.seek(SeekFrom::Start((symbols_table + id as u32 * 18) as u64))?;
                let mut buff = vec![0; 8usize];
                f.read(&mut buff).unwrap();

                let _ = f.read_u32::<LittleEndian>()?;
                let section_number  = f.read_u16::<LittleEndian>()?;

                if section_number == section_id {
                    if buff[0] == 0 {
                        let ptr: [u8; 4] = [ buff[4], buff[5], buff[6], buff[7] ];
                        let val = u32::from_le_bytes(ptr);

                        let mut data = Vec::new();
                        let pos = f.stream_position()?;
                        f.seek(SeekFrom::Start((strings_table + val) as u64))?;
                        let mut bufread = BufReader::new(&f);
                        bufread.read_until(b'\0', &mut data).unwrap();
                        f.seek(SeekFrom::Start(pos))?;

                        let n = String::from_utf8(data).unwrap().trim_matches(char::from(0)).to_string();
                        if n != name {
                            current = Some(n);
                        }
                    }
                }

                if current.is_some() {
                    break;
                }
            }

            if let Some(c) = current {
                functions_names.push(c);
            }

            f.seek(SeekFrom::Start(pos))?;
        }
    }

    let mut output_file = OpenOptions::new().write(true).create(true).open(&format!("build/{filename}.bin")).unwrap();

    let mut current_offset = 0;
    for fname in functions_names {
        if (current_offset % 8) == 4 {
            output_file.write_u32::<LittleEndian>(0)?;
            current_offset += 4;
        }
        assert_eq!(current_offset % 8, 0);

        let func_file = format!("build/{fname}.bin");
        let mut other_file = OpenOptions::new().read(true).open(&func_file).unwrap();
        io::copy(&mut other_file, &mut output_file).unwrap();

        let file_size = std::fs::metadata(&func_file).unwrap().len();
        current_offset += file_size;
    }

    Ok(format!("build/{filename}.bin"))
}

fn cmd_checksum(args: Vec<String>) {
    if args.len() != 2 {
        panic!("'checksum' command requires 2 arguments: <file>.yaml <file>.xex");
    }

    let strbuf = std::fs::read_to_string(args[0].clone()).unwrap();
    let result: Splitter = serde_yaml::from_str(&strbuf).unwrap();
    let input_file = args[1].clone();
    let sha1sum = calculate_sha1sum(&input_file);

    println!("checksum expected: {}", result.sha1);
    println!("checksum calculated: {}", sha1sum);
    if sha1sum == result.sha1 {
        println!("match");
    } else {
        println!("mismatch");
    }
}
