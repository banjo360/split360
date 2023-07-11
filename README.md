# split360

Split a file based on a YAML description file. Inspired by [splat](https://github.com/ethteck/splat).

## example

```yaml
name: Banjo Kazooie                            # mandatory but not used
sha1: 24f81f8058d1be416d95ccfcb5ebd2503eb4fd47 # sha1 of "default.xex"
segments:
  - start: 0x00
    size: 0x100
    name: header
    format: bin                                # dumped "as-is" in `bin/<name>.bin`
  - start: 0xc7a70
    size: 0x40
    name: func_820c5a70
    format: asm                                # will be decompiled to PPC assembly
  - start: 0x5AF456
    size: 0x12
    name: vec3_normalize
    format: c                                  # will be skipped, .c file already exist
```
