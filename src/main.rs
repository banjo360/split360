use std::fs::File;
use serde::Deserialize;
use std::io::Seek;
use std::io::SeekFrom;
use std::io::Read;
use std::io::Write;
use std::env;

use capstone::prelude::*;
use sha1::{Sha1, Digest};

#[derive(Debug, PartialEq, Deserialize)]
struct Segment {
    start: u64,
    size: usize,
    vram: Option<u64>,
    name: String,
    format: String,
}

#[derive(Debug, PartialEq, Deserialize)]
struct Splitter {
    name: String,
    sha1: String,
    segments: Vec<Segment>,
}

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        panic!("Not enough args");
    }

    let strbuf = std::fs::read_to_string(args[1].clone()).unwrap();
    let result: Splitter = serde_yaml::from_str(&strbuf).unwrap();

    if !check_sha1sum("default.xex", &result.sha1) {
        panic!("default.xex doesn't have the correct sha1.");
    }

    let mut f = File::open("default.xex").unwrap();
    println!("{:?}", result.name);
    for seg in result.segments {
        f.seek(SeekFrom::Start(seg.start)).unwrap();
        let mut buff = vec![0u8; seg.size];
        f.read(&mut buff).unwrap();

        println!("Splitting: {}", seg.name);
        std::fs::create_dir_all(&seg.format).unwrap();

        match seg.format.as_str() {
            "bin" => std::fs::write(format!("{}/{}.bin", seg.format, seg.name), buff).unwrap(),
            "asm" => disassemble(&seg, &buff),
            "c" => {},
            _ => panic!("Unknown format '{}'!", seg.format),
        }
    }
}

fn disassemble(segment: &Segment, data: &[u8]) {
    let vram = segment.vram.unwrap();
    std::fs::write(format!("asm/{:X}.bin", vram), data).unwrap();
    
    let cs = Capstone::new()
        .ppc()
        .mode(arch::ppc::ArchMode::Mode32)
        .endian(capstone::Endian::Big)
        .build()
        .expect("Failed to create Capstone object");
    let insns = cs.disasm_all(data, vram).expect("Failed to disassemble");

    let mut f = File::create(format!("asm/{:X}.bin.s", vram)).expect("Unable to create file");
    write!(f, "{}:\n", segment.name).unwrap();
    for i in insns.as_ref() {
        write!(f, "{}\n", i).unwrap();
    }
}

fn check_sha1sum(filename: &str, sha1: &str) -> bool {
    let content = std::fs::read(&filename).unwrap();
    let sha1sum = Sha1::digest(&content);
    let sha1sum = hex::encode(&sha1sum);

    sha1 == sha1sum
}
