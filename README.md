# Assembler
A general 2-pass assembler with an implementation of LC-2200.

## Requirements
The assembler runs on both Python 2 and Python 3.  A instruction set architecture definition file is required along with the assembler.  In this repository, a sample 32-bit LC-2200 ISA definition has been provided in [lc2200.py](lc2200.py).

## Options
The assembler contains multiple options.

`python assembler.py -h` prints:
```
usage: Assembles LC-2200 code into hex or binary. [-h] [-i ISA] [-v] [-l] [-n]
                                                  asmfile

positional arguments:
  asmfile               the .s file to be assembled

optional arguments:
  -h, --help            show this help message and exit
  -i ISA, --isa ISA     define the Python ISA module to load
  -v, --verbose         enable verbose printing of assembler
  -l, --logisim, --hex  output Logisim-compatible RAM image
  -n, --new-line        use new-line character as separator
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

To output with *Logisim* compatibility (hex):
```
python assembly.s -i lc2200 --logisim
```
