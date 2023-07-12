# split360

Split a file based on a YAML description file. Inspired by [splat](https://github.com/ethteck/splat).

## commands

### split

Split a .xex file based on a yaml definition. If no .xex file give, uses `default.xex`.

```
$ split360 split <file>.yaml [<file>.xex]
```

### merge

Generates `<file>.xex` based on a yaml definition. Takes all `.bin` files, compiled code in `build/*.bin` files and concatenate them.

```
$ split360 merge <file>.yaml <file>.xex
```

### checksum

Compares the checksum of `<file>.xex` with the one inside `<file>.yaml`.

```
$ split360 checksum <file>.yaml <file>.xex
```

## example

```yaml
name: Banjo Kazooie                            # mandatory but not used
sha1: 24f81f8058d1be416d95ccfcb5ebd2503eb4fd47 # sha1 of "default.xex"
segments:
  - start: 0x00
    size: 0x100
    name: header
    path: assets                               # only for "bin" format, if not set, defaults to "bin"
    format: bin                                # dumped "as-is" in `<path>/<name>.bin`
  - start: 0xc7a70
    size: 0x40
    name: func_820c5a70
    format: asm                                # will be decompiled to PPC assembly
  - start: 0x5AF456
    size: 0x12
    name: vec3_normalize
    format: c                                  # will be skipped, .c file already exist
```

The bytes that are not covered in the file are dump in the "bin" directory. In this example, it will contains the following files:
- `bin_100`: 0x100 to 0xc7a6f
- `bin_c7ab0`: 0xc7ab0 to 0x5af455
- `bin_5af468`: 0x5af468 to the end of the file.
