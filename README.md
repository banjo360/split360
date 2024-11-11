# split360

Split a file based on a YAML description file. Inspired by [splat](https://github.com/ethteck/splat).

## commands

### split

Split a .xex file based on a yaml definition. If no .xex file give, uses `default.xex`.

```
$ split360 split <file>.yaml [<file>.xex]
```

### merge

Generates `<file>.xex` based on a yaml definition. Takes all `.bin` files (raw in `bin/` or compiled in `build/`) and concatenate them.

```
$ split360 merge <file>.yaml <file>.xex
```

### checksum

Compares the checksum of `<file>.xex` with the one inside `<file>.yaml`.

```
$ split360 checksum <file>.yaml <file>.xex
```

## segments keys

### start

The start of the segment in the .xex file.

### size

The size of the segment.

### name

The filename (without extension) of the file containing the data (e.g. `<name>.c` or `<name>.bin`).

### format

* `bin`: extract the segment as-is in `bin/<name>.bin`.
* `asm`: extract the segment as-is in `asm/<name>.bin` and disassemble it in `bin/<name>.s`.
* `c`: do nothing on extraction if `segment` is set otherwise disassemble it in the `matching/` directory.

### segment

* *missing*: This segment is the `.text` segment and is defined in a `.c` file inside the `src` directory.
* `data`: This is the `.data` segment extracted from the compiled `src/<name>.c` file.
* `rdata`: This is the `.rdata` segment extracted from the compiled `src/<name>.c` file.

## example

```yaml
name: Banjo Kazooie                            # mandatory but not used
sha1: 24f81f8058d1be416d95ccfcb5ebd2503eb4fd47 # sha1 of "default.xex"
segments:
  - start: 0x00
    size: 0x100
    name: header
    path: assets         # only for "bin" format, if not set, defaults to "bin"
    format: bin          # dumped "as-is" in `<path>/<name>.bin`
  - start: 0xc7a70
    size: 0x40
    name: func_820c5a70
    format: asm          # will be decompiled to PPC assembly
  - start: 0x5AF456
    size: 0x12
    name: vec3           # filename "vec3.c"
    format: c            # will be skipped, .c file already exist
                         # missing "segment" means a disassembly will be generated in matching/
  - start: 0x645cc6
    size: 0x42
    name: vec3           # same as above
    format: c            # same as above
    segment: rdata       # must be omitted for .text, but mandatory for ".data" or ".rdata"
```

The bytes that are not covered in the file are dumped in the `bin/` directory. In this example, it will contains the following files:
- `bin_100.bin`: 0x100 to 0xc7a6f
- `bin_c7ab0.bin`: 0xc7ab0 to 0x5af455
- `bin_5af468.bin`: 0x5af468 to 0x645cc5
- `bin_645d07.bin`: 0x645d07 to the end of the file.

[Banjo-Kazooie example file](https://github.com/banjo360/bk360/blob/main/bk.yaml)
