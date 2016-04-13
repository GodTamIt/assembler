# Assembler
A general 2-pass assembler with an implementation of LC-2200.

## Requirements
The assembler runs on both Python 2 and Python 3.  A instruction set architecture definition file is required along with the assembler.  In this repository, a sample 32-bit LC-2200 ISA definition has been provided in [lc2200.py](lc2200.py).

## Options
The assembler contains multiple options.

`python assembler.py -h` prints:
```
usage: Assembles LC-2200 code into hex or binary. [-h] [-i ISA] [-v] [--hex]
                                                  [-s SEPARATOR]
                                                  asmfile

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
python <assembly_file> -i <isa_definition>
```

Example usage with the `lc2200.py` definition:
```
python assembly.s -i lc2200
```

To output assembled code in hexadecimal (compatible with *Logisim* images):
```
python assembly.s -i lc2200 --logisim
```

To separate entries by new line:
```
python assembly.s -i lc2200 --separator \n
```