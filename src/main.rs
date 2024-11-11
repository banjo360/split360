use std::sync::LazyLock;
use std::fs::OpenOptions;
use std::fs::File;
use serde::Deserialize;
use std::io;
use std::io::Seek;
use std::io::Read;
use std::io::Write;
use std::env;
use std::collections::HashMap;
use capstone::prelude::*;
use sha1::{Sha1, Digest};
use regex::Regex;

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
    vram_offset: u64,
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

    let mut symbols = HashMap::new();

    if std::fs::metadata("addresses.txt").is_ok() {
        for line in std::fs::read_to_string("addresses.txt").unwrap().lines() {
            let linedata: Vec<_> = line.split(" ").collect();
            assert_eq!(linedata.len(), 2);
            
            let addr = u64::from_str_radix(&linedata[0], 16).unwrap();
            let name = linedata[1].to_string();
            symbols.insert(addr, name);
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
                "asm" => disassemble(&seg.name, &buff, seg.start + result.vram_offset, &symbols, "asm"),
                "c" => {
                    if seg.segment.is_none() {
                        disassemble(&seg.name, &buff, seg.start + result.vram_offset, &symbols, "matching");
                    }
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

static ADDR_REGEX: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"0x[0-9a-zA-Z]{8}").unwrap());

fn disassemble(name: &str, data: &[u8], addr: u64, symbols: &HashMap::<u64, String>, directory: &str) {
    std::fs::create_dir_all(directory).unwrap();
    std::fs::write(format!("{}/{}.bin", directory, name), data).unwrap();

    let cs = Capstone::new()
        .ppc()
        .mode(arch::ppc::ArchMode::Mode32)
        .endian(capstone::Endian::Big)
        .build()
        .expect("Failed to create Capstone object");
    let insns = cs.disasm_all(data, addr).expect("Failed to disassemble");

    let mut f = File::create(format!("{}/{}.s", directory, name)).expect("Unable to create file");
    for i in insns.as_ref() {
        if let Some(name) = symbols.get(&i.address()) {
            write!(f, "{name}:\n").unwrap();
        }

        let op_str = format!("{}", i.op_str().unwrap());

        if let Some(caps) = ADDR_REGEX.captures(&op_str) {
            assert_eq!(caps.len(), 1);

            let (start, end) = if let Some(cap) = caps.get(0) {
                (cap.start(), cap.end())
            } else {
                panic!("shouldn't be triggered thanks to the assert above.");
            };

            assert!(start != end);

            let mut output_str = String::new();
            if start > 0 {
                output_str.push_str(&op_str[..start]);
            }

            let addr_str = u64::from_str_radix(&op_str[(start+2)..end], 16).unwrap();
            output_str.push_str(if let Some(symname) = symbols.get(&addr_str) {
                symname
            } else {
                &op_str[start..end]
            });

            if end < op_str.len() - 1 {
                output_str.push_str(&op_str[end..]);
            }

            write!(f, "{:#x}: {} {}\n", i.address(), i.mnemonic().unwrap(), output_str).unwrap();
        }
        else
        {
            write!(f, "{}\n", i).unwrap();
        }
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

    let mut output_file = OpenOptions::new().write(true).create(true).truncate(true).open(&output_filename).unwrap();

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
                _ => panic!("Unknown format '{f}'.")
            };

            let file_size = std::fs::metadata(&binfile).expect(&format!("{} does not exist", binfile)).len();
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

fn cmd_checksum(args: Vec<String>) {
    if args.len() != 2 {
        panic!("'checksum' command requires 2 arguments: <file>.yaml <file>.xex");
    }

    let strbuf = std::fs::read_to_string(args[0].clone()).unwrap();
    let result: Splitter = serde_yaml::from_str(&strbuf).unwrap();
    let input_file = args[1].clone();
    let sha1sum = calculate_sha1sum(&input_file);

    if sha1sum == result.sha1 {
        println!("MATCH");
    } else {
        println!("MISMATCH");
        println!("checksum expected: {}", result.sha1);
        println!("checksum calculated: {}", sha1sum);
    }
}
