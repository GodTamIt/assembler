# Assembler
A general 2-pass assembler with implementations of LC-2200 and LC3-2200a.

## Requirements
The assembler runs on any version of Python 2.6+.  An instruction set architecture definition file is required along with the assembler.  In this repository, several sample ISA definitions have been provided (see below).

## Sample Definitions
* [LC-2200 (32-bit)](lc2200.py)
* [LC3-2200a (32-bit)](lc32200a.py)

## Options
The assembler contains multiple options.

`python assembler.py -h` prints:
```
usage: Assembles generic ISA-defined assembly code into hex or binary.
       [-h] [-i ISA] [-v] [--hex] [-s SEPARATOR] asmfile

positional arguments:
  asmfile               the .s file to be assembled

optional arguments:
  -h, --help            show this help message and exit
  -i ISA, --isa ISA     define the Python ISA module to load [default: isa]
  -v, --verbose         enable verbose printing of assembler
  --hex, --logisim      assemble code into hexadecimal (Logisim-compatible)
  -s SEPARATOR, --separator SEPARATOR
                        the separator to use between instructions (accepts \s
                        for space and standard escape characters) [default:
                        \s]

```

## How to Use
Typical usage:
```
python assembler.py <assembly_file> -i <isa_definition>
```

Example usage with the `lc2200.py` definition:
```
python assembler.py assembly.s -i lc2200
```

To output assembled code in hexadecimal (compatible with *Logisim* images):
```
python assembler.py assembly.s -i lc2200 --logisim
```

To separate entries by new line:
```
python assembler.py assembly.s -i lc2200 --separator \n
```
