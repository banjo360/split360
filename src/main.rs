#![allow(unused)]

use std::fs::File;
use serde::Deserialize;
use std::io::Seek;
use std::io::SeekFrom;
use std::io::Read;
use std::io::Write;
use std::env;
use std::process::Command;
use std::collections::HashMap;

use capstone::prelude::*;
use sha1::{Sha1, Digest};

#[derive(Debug, PartialEq, Deserialize)]
struct Segment {
    start: u64,
    size: usize,
    name: String,
    path: Option<String>,
    format: String,
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
    while index < result.segments.len() {
        let seg = &result.segments[index];

        if curr_addr < seg.start {
            std::fs::create_dir_all("bin").unwrap();

            let size = (seg.start - curr_addr) as usize;
            let filename = format!("bin/bin_{:x}.bin", curr_addr);

            dump_bin(&mut f, size, &filename);

            curr_addr = seg.start;
        } else {
            let size = seg.size;

            assert_eq!(f.stream_position().unwrap(), curr_addr);
            let mut buff = vec![0u8; size as usize];
            f.read(&mut buff).unwrap();

            match seg.format.as_str() {
                "bin" => {
                    let dir = if let Some(path) = &seg.path { &path } else { "bin" };
                    std::fs::create_dir_all(dir).unwrap();
                    std::fs::write(format!("{}/{}.bin", dir, seg.name), buff).unwrap()
                },
                "asm" => disassemble(&seg, &buff, &symbols),
                "c" => {},
                _ => panic!("Unknown format '{}'!", seg.format),
            }

            curr_addr += (seg.size as u64);
            index += 1;
        }
    }
}

fn dump_bin(file: &mut File, size: usize, filename: &str) {
    let mut buff = vec![0u8; size];
    file.read(&mut buff).unwrap();
    std::fs::write(filename, buff).unwrap();
}

fn disassemble(segment: &Segment, data: &[u8], symbols: &HashMap::<String, u64>) {
    std::fs::create_dir_all("asm").unwrap();
    std::fs::write(format!("asm/{:X}.bin", segment.start), data).unwrap();
    
    let vram = if symbols.contains_key(&segment.name) { symbols[&segment.name] } else { 0 };

    let cs = Capstone::new()
        .ppc()
        .mode(arch::ppc::ArchMode::Mode32)
        .endian(capstone::Endian::Big)
        .build()
        .expect("Failed to create Capstone object");
    let insns = cs.disasm_all(data, vram).expect("Failed to disassemble");

    let mut f = File::create(format!("asm/{:X}.bin.s", segment.start)).expect("Unable to create file");
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
    let output_file = args[1].clone();

    let mut cat_command = Command::new("/bin/cat");

    let mut curr_addr = 0;
    let mut index = 0;
    while index < result.segments.len() {
        let seg = &result.segments[index];

        let filename = if seg.start == curr_addr {
            let n = &seg.name;
            let f = &seg.format;
            curr_addr += (seg.size as u64);
            index += 1;
            match f.as_str() {
                "bin" => {
                    let dir = if let Some(path) = &seg.path { &path } else { "bin" };
                    format!("bin/{}.bin", n)
                },
                "c" => format!("build/{}.obj.bin", n),
                _ => panic!("Unknown format '{}'.", f)
            }
        } else {
            let tmp_addr = curr_addr;
            curr_addr = seg.start;
            format!("bin/bin_{:x}.bin", tmp_addr)
        };

        cat_command.arg(&filename);
    }

    let output_file = File::create(output_file).unwrap();
    cat_command.stdout(output_file);

    let status = cat_command.status().expect("failed to execute process");
    assert!(status.success());
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
