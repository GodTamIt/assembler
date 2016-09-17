import re

"""lc3-2000a.py: A definition of the LC3-2200a architecture."""
__author__ = "Christopher Tam"


# Define the name of the architecture
__name__ = 'LC3-2200a'

# Define overall architecture widths (in bits)
BIT_WIDTH = 32
# Define opcode widths (in bits)
OPCODE_WIDTH = 4
# Define register specifier widths (in bits)
REGISTER_WIDTH = 4
    
ALIASES = {
    '.word' :   'fill',
    '.fill' :   'fill',
    'str'   :   'STR',
    'brn'   :   'br',
    'brz'   :   'br',
    'brp'   :   'br',
    'brnz'  :   'br',
    'brzp'  :   'br',
    'brnp'  :   'br',
    'brnzp' :   'br',
    'shf'   :   None,
    'shfll' :   'shf',
    'shfrl' :   'shf',
    'shfra' :   'shf'
}
    
REGISTERS = {
        '$zero' :   0,
        '$at'   :   1,
        '$v0'   :   2,
        '$a0'   :   3,
        '$a1'   :   4,
        '$a2'   :   5,
        '$t0'   :   6,
        '$t1'   :   7,
        '$t2'   :   8,
        '$s0'   :   9,
        '$s1'   :   10,
        '$s2'   :   11,
        '$k0'   :   12,
        '$sp'   :   13,
        '$fp'   :   14,
        '$ra'   :   15}


SYMBOL_TABLE = {}


# Public Functions
def is_blank(line):
    """Return whether a line is blank and not an instruction."""
    return __RE_BLANK__.match(line) is not None
    
def get_parts(line):
    """Break down an instruction into 3 parts: Label, Opcode, Operand"""
    m = __RE_PARTS__.match(line)
    try:
        return m.group('Label'), m.group('Opcode'), m.group('Operands')
    except:
        return None

def instruction_class(name):
    """Translate a given instruction name to its corresponding class name."""
    return ALIASES.get(name, name)

# Private Variables
__OFFSET_SIZE__ = BIT_WIDTH - OPCODE_WIDTH - (REGISTER_WIDTH * 2)
assert(__OFFSET_SIZE__ > 0) # Sanity check

__UNUSED_SIZE__ = BIT_WIDTH - OPCODE_WIDTH - (REGISTER_WIDTH * 3)
assert(__UNUSED_SIZE__ > 0) # Sanity check

__SHF_IMM_SIZE__ = 5

__SHF_UNUSED_SIZE__ = __OFFSET_SIZE__ - __SHF_IMM_SIZE__ - 2
assert(__SHF_UNUSED_SIZE__ > 0) # Sanity check


__RE_BLANK__ = re.compile(r'^\s*(!.*)?$')
__RE_PARTS__ = re.compile(r'^\s*((?P<Label>\w+):)?\s*((?P<Opcode>\.?[\w]+)(?P<Operands>[^!]*))?(!.*)?')
__RE_HEX__ = re.compile(r'0x[A-z0-9]*')
__RE_R__ = re.compile(r'^\s*(?P<RX>\$\w+?)\s*,\s*(?P<RY>\$\w+?)\s*,\s*(?P<RZ>\$\w+?)\s*$')
__RE_JALR__ = re.compile(r'^\s*(?P<AT>\$\w+?)\s*,\s*(?P<RA>\$\w+?)\s*$')
__RE_I__ = re.compile(r'^\s*(?P<RX>\$\w+?)\s*,\s*(?P<RY>\$\w+?)\s*,\s*(?P<Offset>\S+?)\s*$')
__RE_OFF__ = re.compile(r'^\s*(?P<RX>\$\w+?)\s*,\s*(?P<Offset>\S+?)\s*\((?P<RY>\$\w+?)\)\s*$')
__RE_LEA__ = re.compile(r'^\s*(?P<RX>\$\w+?)\s*,\s*(?P<Offset>\S+?)\s*$')
__RE_BR__ = re.compile(r'^\s*(?P<Offset>\S+?)\s*$')

# Private Functions
def __zero_extend__(binary, target, pad_right=False):
    if binary.startswith('0b'):
        binary = binary[2:]
    
    zeros = '0' * (target - len(binary))
    if pad_right:
        return binary + zeros
    else:
        return zeros + binary
    
def __sign_extend__(binary, target):
    if binary.startswith('0b'):
        binary = binary[2:]

    return binary[0] * (target - len(binary)) + binary
    
def __bin2hex__(binary):
    return '%0*X' % ((len(binary) + 3) // 4, int(binary, 2))
    
def __hex2bin__(hexadecimal):
    return bin(int(hexadecimal, 16))[2:]
    
def __dec2bin__(num, bits):
    """Compute the 2's complement binary of an int value."""
    return format(num if num >= 0 else (1 << bits) + num, '0{}b'.format(bits))

def __parse_value__(offset, size, pc=None, unsigned=False):
    bin_offset = None
    
    if type(offset) is str:
        if pc is not None and offset in SYMBOL_TABLE:
            offset = SYMBOL_TABLE[offset] - (pc + 1)
        elif offset.startswith('0x'):
            try:
                bin_offset = __hex2bin__(offset)
            except:
                raise RuntimeError("'{}' is not in a valid hexadecimal format.".format(offset))
                
            if len(bin_offset) > size:
                raise RuntimeError("'{}' is too large for {}.".format(offset, __name__))
                
            bin_offset = __zero_extend__(bin_offset, size)
        elif offset.startswith('0b'):
            try:
                bin_offset = bin(int(offset))
            except:
                raise RuntimeError("'{}' is not in a valid binary format.".format(offset))
                
            if len(bin_offset) > size:
                raise RuntimeError("'{}' is too large for {}.".format(offset, __name__))
                
            bin_offset = __zero_extend__(bin_offset, size)
            
    if bin_offset is None:
        try:
            offset = int(offset)
        except:
            if pc is not None:
                raise RuntimeError("'{}' cannot be resolved as a label or a value.".format(offset))
            else:
                raise RuntimeError("'{}' cannot be resolved as a value.".format(offset))
        
        if unsigned:
            bound = (2**size)

            # >= bound because range is [0, 2^n - 1]
            if offset >= bound:
                raise RuntimeError("'{}' is too large (values) or too far away (labels) for {}.".format(offset, __name__))
        else:
            bound = 2**(size - 1)

            if offset < -bound or offset >= bound:
                raise RuntimeError("'{}' is too large (values) or too far away (labels) for {}.".format(offset, __name__))
            
        bin_offset = __dec2bin__(offset, size)
    
    return bin_offset

def __parse_r__(operands):
    # Define result
    result_list = []
    
    match = __RE_R__.match(operands)
    
    if match is None:
        raise RuntimeError("Operands '{}' are in an incorrect format.".format(operands.strip()))
    
    for op in (match.group('RX'), match.group('RY'), match.group('RZ')):
        if op in REGISTERS:
            result_list.append(__zero_extend__(bin(REGISTERS[op])[2:], REGISTER_WIDTH))
        else:
            raise RuntimeError("Register identifier '{}' is not valid in {}.".format(op, __name__))

    # Insert unused bits
    result_list.insert(2, '0' * __UNUSED_SIZE__)
    
    return ''.join(result_list)

def __parse_i__(operands, is_offset=False, pc=None):
    # Define result
    result_list = []
    
    match = __RE_OFF__.match(operands) if is_offset else __RE_I__.match(operands)
    
    if match is None:
        raise RuntimeError("Operands '{}' are in an incorrect format.".format(operands.strip()))
    
    for op in (match.group('RX'), match.group('RY')):
        if op in REGISTERS:
            result_list.append(__zero_extend__(bin(REGISTERS[op]), REGISTER_WIDTH))
        else:
            raise RuntimeError("Register identifier '{}' is not valid in {}.".format(op, __name__))
            
    result_list.append(__parse_value__(match.group('Offset'), __OFFSET_SIZE__, pc))
    
    return ''.join(result_list)

def __parse_jalr__(operands):
    # Define result
    result_list = []
    
    match = __RE_JALR__.match(operands)
    
    if match is None:
        raise RuntimeError("Operands '{}' are in an incorrect format.".format(operands.strip()))
    
    for op in (match.group('RA'), match.group('AT')):
        if op in REGISTERS:
            result_list.append(__zero_extend__(bin(REGISTERS[op]), REGISTER_WIDTH))
        else:
            raise RuntimeError("Register identifier '{}' is not valid in {}.".format(op, __name__))
            
    return ''.join(result_list)

def __parse_lea__(operands, pc):
    match = __RE_LEA__.match(operands)
    if match is None:
        raise RuntimeError("Operands '{}' are in an incorrect format.".format(operands.strip()))
    
    result_list = []

    RX = match.group('RX')
    label = match.group('Offset')
    
    if RX in REGISTERS:
        result_list.append(__zero_extend__(bin(REGISTERS[RX]), REGISTER_WIDTH))
    else:
        raise RuntimeError("Register identifier '{}' is not valid in {}.".format(op, __name__))

    result_list.append('0' * REGISTER_WIDTH) # Unused bits
    result_list.append(__parse_value__(match.group('Offset'), __OFFSET_SIZE__, pc))

    return ''.join(result_list)

def __parse_br__(operands, pc):
    match = __RE_BR__.match(operands)
    if match is None:
        raise RuntimeError("Operands '{}' are in an incorrect format.".format(operands.strip()))

    return __parse_value__(match.group('Offset'), __OFFSET_SIZE__, pc)

def __parse_shf__(operands, A, D):
    match = __RE_I__.match(operands)
    if match is None:
        raise RuntimeError("Operands '{}' are in an incorrect format.".format(operands.strip()))

    result_list = []

    for op in (match.group('RX'), match.group('RY')):
        if op in REGISTERS:
            result_list.append(__zero_extend__(bin(REGISTERS[op]), REGISTER_WIDTH))
        else:
            raise RuntimeError("Register identifier '{}' is not valid in {}.".format(op, __name__))

    result_list.append(A)
    result_list.append(D)
    result_list.append('0' * __SHF_UNUSED_SIZE__)

    result_list.append(__parse_value__(match.group('Offset'), __SHF_IMM_SIZE__, unsigned=True))

    return ''.join(result_list)


class Instruction:
    """
    This is the base class that all implementations of instructions must override.
    """
    @staticmethod
    def opcode():
        """Return the operation code for the given instruction as an integer."""
        raise NotImplementedError()
    
    @staticmethod
    def size():
        """Return how many binary machine-level instructions the instruction will expand to."""
        raise NotImplementedError()
        
    @staticmethod
    def binary(operands, **kwargs):
        """Assemble the instruction into binary form.
        
        Keyword arguments:
        operands -- a string representation of the operands of the instruction.
        **kwargs -- additional necessary arguments for the instruction.
        
        Returns an iterable representation of the binary instruction(s).
        """
        raise NotImplementedError()
        
    @staticmethod
    def hex(operands, **kwargs):
        """Assemble the instruction into hexadecimal form.
        
        Keyword arguments:
        operands -- a string representation of the operands of the instruction.
        **kwargs -- additional necessary arguments for the instruction.
        
        Returns an iterable representation of the hexadecimal instruction(s).
        """
        raise NotImplementedError()

class add(Instruction):
    @staticmethod
    def opcode():
        return 0
        
    @staticmethod
    def size():
        return 1
        
    @staticmethod
    def binary(operands, **kwargs):
        opcode = __zero_extend__(bin(add.opcode()), OPCODE_WIDTH)
        operands = __parse_r__(operands)
        return [opcode + operands]
        
    @staticmethod
    def hex(operands, **kwargs):
        return [__bin2hex__(instr) for instr in add.binary(operands, **kwargs)]


class addi(Instruction):
    @staticmethod
    def opcode():
        return 1
        
    @staticmethod
    def size():
        return 1
        
    @staticmethod
    def binary(operands, **kwargs):
        opcode = __zero_extend__(bin(addi.opcode()), OPCODE_WIDTH)
        operands = __parse_i__(operands)
        return [opcode + operands]
        
    @staticmethod
    def hex(operands, **kwargs):
        return [__bin2hex__(instr) for instr in addi.binary(operands, **kwargs)]

class nand(Instruction):
    @staticmethod
    def opcode():
        return 2
        
    @staticmethod
    def size():
        return 1
        
    @staticmethod
    def binary(operands, **kwargs):
        opcode = __zero_extend__(bin(nand.opcode()), OPCODE_WIDTH)
        operands = __parse_r__(operands)
        return [opcode + operands]
        
    @staticmethod
    def hex(operands, **kwargs):
        return [__bin2hex__(instr) for instr in nand.binary(operands, **kwargs)]


class br(Instruction):
    @staticmethod
    def opcode():
        return 3
        
    @staticmethod
    def size():
        return 1
        
    @staticmethod
    def binary(operands, **kwargs):
        assert('pc' in kwargs) # Sanity check
        assert('instruction' in kwargs) # Sanity check

        pc = kwargs['pc']
        instr = kwargs['instruction']

        if instr == 'br':
            instr = 'brnzp'
        instr = instr[2:]

        result = []

        result.append(__zero_extend__(bin(br.opcode()), OPCODE_WIDTH))  # Opcode
        result.append('0' * 5)                                          # Unused bits
        for flag in 'nzp':
            result.append('1' if flag in instr else '0')                # Branch control bits
        result.append(__parse_br__(operands, pc))                       # Offset value

        return [''.join(result)]
        
    @staticmethod
    def hex(operands, **kwargs):
        return [__bin2hex__(instr) for instr in br.binary(operands, **kwargs)]
        

class jalr(Instruction):
    @staticmethod
    def opcode():
        return 4
        
    @staticmethod
    def size():
        return 1
        
    @staticmethod
    def binary(operands, **kwargs):
        opcode = __zero_extend__(bin(jalr.opcode()), OPCODE_WIDTH)
        operands = __parse_jalr__(operands)
        return [__zero_extend__(opcode + operands, BIT_WIDTH, pad_right=True)]
        
    @staticmethod
    def hex(operands, **kwargs):
        return [__bin2hex__(instr) for instr in jalr.binary(operands, **kwargs)]


class ldr(Instruction):
    @staticmethod
    def opcode():
        return 5
        
    @staticmethod
    def size():
        return 1
        
    @staticmethod
    def binary(operands, **kwargs):
        opcode = __zero_extend__(bin(ldr.opcode()), OPCODE_WIDTH)
        operands = __parse_i__(operands, is_offset=True)
        return [opcode + operands]
        
    @staticmethod
    def hex(operands, **kwargs):
        return [__bin2hex__(instr) for instr in ldr.binary(operands, **kwargs)]
        

class lea(Instruction):
    @staticmethod
    def opcode():
        return 6
        
    @staticmethod
    def size():
        return 1
        
    @staticmethod
    def binary(operands, **kwargs):
        assert('pc' in kwargs)  # Sanity check

        opcode = __zero_extend__(bin(lea.opcode()), OPCODE_WIDTH)
        operands = __parse_lea__(operands, kwargs['pc'])
        return [__zero_extend__(opcode + operands, BIT_WIDTH, pad_right=True)]
        
    @staticmethod
    def hex(operands, **kwargs):
        return [__bin2hex__(instr) for instr in lea.binary(operands, **kwargs)]


class STR(Instruction):
    @staticmethod
    def opcode():
        return 7
        
    @staticmethod
    def size():
        return 1
        
    @staticmethod
    def binary(operands, **kwargs):
        opcode = __zero_extend__(bin(STR.opcode()), OPCODE_WIDTH)
        operands = __parse_i__(operands, is_offset=True)
        return [opcode + operands]
        
    @staticmethod
    def hex(operands, **kwargs):
        return [__bin2hex__(instr) for instr in STR.binary(operands, **kwargs)]

class shf(Instruction):
    @staticmethod
    def opcode():
        return 8
        
    @staticmethod
    def size():
        return 1
        
    @staticmethod
    def binary(operands, **kwargs):
        assert('instruction' in kwargs)

        instr = kwargs['instruction']

        if instr == 'shfll':
            A, D = '0', '0'
        elif instr == 'shfrl':
            A, D = '0', '1'
        elif instr == 'shfra':
            A, D = '1', '1'
        else:
            raise RuntimeError("'shf' instruction could not be assembled.")
        
        opcode = __zero_extend__(bin(shf.opcode()), OPCODE_WIDTH)
        operands = __parse_shf__(operands, A, D)

        return [opcode + operands]
        
    @staticmethod
    def hex(operands, **kwargs):
        return [__bin2hex__(instr) for instr in shf.binary(operands, **kwargs)]

class halt(Instruction):
    @staticmethod
    def opcode():
        return 15
        
    @staticmethod
    def size():
        return 1
        
    @staticmethod
    def binary(operands, **kwargs):
        opcode = __zero_extend__(bin(halt.opcode()), OPCODE_WIDTH)
        return [__zero_extend__(opcode, BIT_WIDTH, pad_right=True)]
        
    @staticmethod
    def hex(operands, **kwargs):
        return [__bin2hex__(instr) for instr in halt.binary(operands, **kwargs)]


class noop(Instruction):
    """noop
    
    Equivalent to:
    add $zero, $zero, $zero
    """

    @staticmethod
    def opcode():
        return None
        
    @staticmethod
    def size():
        return add.size()
        
    @staticmethod
    def binary(operands, **kwargs):
        return add.binary('$zero, $zero, $zero', **kwargs)
        
    @staticmethod
    def hex(operands, **kwargs):
        return [__bin2hex__(instr) for instr in noop.binary(operands, **kwargs)]

class ret(Instruction):
    """ret
    
    Equivalent to:
    jalr $ra, $zero
    """

    @staticmethod
    def opcode():
        return None
        
    @staticmethod
    def size():
        return jalr.size()
        
    @staticmethod
    def binary(operands, **kwargs):
        return jalr.binary('$ra, $zero', **kwargs)
        
    @staticmethod
    def hex(operands, **kwargs):
        return [__bin2hex__(instr) for instr in ret.binary(operands, **kwargs)]

class fill(Instruction):
    @staticmethod
    def opcode():
        return None
        
    @staticmethod
    def size():
        return 1
        
    @staticmethod
    def binary(operands, **kwargs):
        if type(operands) is str:
            operands = operands.strip()
        return [__parse_value__(operands, BIT_WIDTH)]
        
    @staticmethod
    def hex(operands, **kwargs):
        return [__bin2hex__(instr) for instr in fill.binary(operands, **kwargs)]
        
