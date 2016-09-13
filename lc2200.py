import re

"""lc2200.py: A definition of the LC-2200 architecture."""
__author__ = "Christopher Tam"


# Define the name of the architecture
__name__ = 'LC-2200'

# Define overall architecture widths (in bits)
BIT_WIDTH = 32
# Define opcode widths (in bits)
OPCODE_WIDTH = 4
# Define register specifier widths (in bits)
REGISTER_WIDTH = 4
    
ALIASES = {
    '.word':'fill',
    '.fill':'fill'
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
assert(__OFFSET_SIZE__ > 0)  # Sanity check

__RE_BLANK__ = re.compile(r'^\s*(!.*)?$')
__RE_PARTS__ = re.compile(r'^\s*((?P<Label>\w+):)?\s*((?P<Opcode>\.?[\w]+)(?P<Operands>[^!]*))?(!.*)?')
__RE_HEX__ = re.compile(r'0x[A-z0-9]*')
__RE_R__ = re.compile(r'^\s*(?P<RX>\$\w+?)\s*,\s*(?P<RY>\$\w+?)\s*,\s*(?P<RZ>\$\w+?)\s*$')
__RE_J__ = re.compile(r'^\s*(?P<RX>\$\w+?)\s*,\s*(?P<RY>\$\w+?)\s*$')
__RE_I__ = re.compile(r'^\s*(?P<RX>\$\w+?)\s*,\s*(?P<RY>\$\w+?)\s*,\s*(?P<Offset>\S+?)\s*$')
__RE_MEM__ = re.compile(r'^\s*(?P<RX>\$\w+?)\s*,\s*(?P<Offset>\S+?)\s*\((?P<RY>\$\w+?)\)\s*$')
__RE_LA__ = re.compile(r'^\s*(?P<RX>\$\w+?)\s*,\s*(?P<Label>\w+?)\s*$')

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

def __parse_value__(offset, size, pc=None):
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
            
    return ''.join(result_list)

def __parse_i__(operands, is_mem=False, pc=None):
    # Define result
    result_list = []
    
    match = __RE_MEM__.match(operands) if is_mem else __RE_I__.match(operands)
    
    if match is None:
        raise RuntimeError("Operands '{}' are in an incorrect format.".format(operands.strip()))
    
    for op in (match.group('RX'), match.group('RY')):
        if op in REGISTERS:
            result_list.append(__zero_extend__(bin(REGISTERS[op]), REGISTER_WIDTH))
        else:
            raise RuntimeError("Register identifier '{}' is not valid in {}.".format(op, __name__))
            
    result_list.append(__parse_value__(match.group('Offset'), __OFFSET_SIZE__, pc))
    
    return ''.join(result_list)

def __parse_j__(operands):
    # Define result
    result_list = []
    
    match = __RE_J__.match(operands)
    
    if match is None:
        raise RuntimeError("Operands '{}' are in an incorrect format.".format(operands.strip()))
    
    for op in (match.group('RX'), match.group('RY')):
        if op in REGISTERS:
            result_list.append(__zero_extend__(bin(REGISTERS[op]), REGISTER_WIDTH))
        else:
            raise RuntimeError("Register identifier '{}' is not valid in {}.".format(op, __name__))
            
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
        return [__zero_extend__(opcode + operands, BIT_WIDTH, pad_right=True)]
        
    @staticmethod
    def hex(operands, **kwargs):
        return [__bin2hex__(instr) for instr in add.binary(operands, **kwargs)]

class neg(Instruction):
    @staticmethod
    def opcode():
        return 1
        
    @staticmethod
    def size():
        return 1
        
    @staticmethod
    def binary(operands, **kwargs):
        opcode = __zero_extend__(bin(neg.opcode()), OPCODE_WIDTH)
        operands = __parse_j__(operands)
        return [__zero_extend__(opcode + operands, BIT_WIDTH, pad_right=True)]
        
    @staticmethod
    def hex(operands, **kwargs):
        return [__bin2hex__(instr) for instr in neg.binary(operands, **kwargs)]


class addi(Instruction):
    @staticmethod
    def opcode():
        return 2
        
    @staticmethod
    def size():
        return 1
        
    @staticmethod
    def binary(operands, **kwargs):
        opcode = __zero_extend__(bin(addi.opcode()), OPCODE_WIDTH)
        operands = __parse_i__(operands)
        return [__zero_extend__(opcode + operands, BIT_WIDTH, pad_right=True)]
        
    @staticmethod
    def hex(operands, **kwargs):
        return [__bin2hex__(instr) for instr in addi.binary(operands, **kwargs)]
        

class lw(Instruction):
    @staticmethod
    def opcode():
        return 3
        
    @staticmethod
    def size():
        return 1
        
    @staticmethod
    def binary(operands, **kwargs):
        opcode = __zero_extend__(bin(lw.opcode()), OPCODE_WIDTH)
        operands = __parse_i__(operands, is_mem=True)
        return [__zero_extend__(opcode + operands, BIT_WIDTH, pad_right=True)]
        
    @staticmethod
    def hex(operands, **kwargs):
        return [__bin2hex__(instr) for instr in lw.binary(operands, **kwargs)]
        

class sw(Instruction):
    @staticmethod
    def opcode():
        return 4
        
    @staticmethod
    def size():
        return 1
        
    @staticmethod
    def binary(operands, **kwargs):
        opcode = __zero_extend__(bin(sw.opcode()), OPCODE_WIDTH)
        operands = __parse_i__(operands, is_mem=True)
        return [__zero_extend__(opcode + operands, BIT_WIDTH, pad_right=True)]
        
    @staticmethod
    def hex(operands, **kwargs):
        return [__bin2hex__(instr) for instr in sw.binary(operands, **kwargs)]

class beq(Instruction):
    @staticmethod
    def opcode():
        return 5
        
    @staticmethod
    def size():
        return 1
        
    @staticmethod
    def binary(operands, **kwargs):
        assert('pc' in kwargs)  # Sanity check
    
        opcode = __zero_extend__(bin(beq.opcode()), OPCODE_WIDTH)
        operands = __parse_i__(operands, kwargs['pc'])
        return [__zero_extend__(opcode + operands, BIT_WIDTH, pad_right=True)]
        
    @staticmethod
    def hex(operands, **kwargs):
        return [__bin2hex__(instr) for instr in beq.binary(operands, **kwargs)]


class jalr(Instruction):
    @staticmethod
    def opcode():
        return 6
        
    @staticmethod
    def size():
        return 1
        
    @staticmethod
    def binary(operands, **kwargs):
        opcode = __zero_extend__(bin(jalr.opcode()), OPCODE_WIDTH)
        operands = __parse_j__(operands)
        return [__zero_extend__(opcode + operands, BIT_WIDTH, pad_right=True)]
        
    @staticmethod
    def hex(operands, **kwargs):
        return [__bin2hex__(instr) for instr in jalr.binary(operands, **kwargs)]


class spop(Instruction):
    @staticmethod
    def opcode():
        return 7
        
    @staticmethod
    def size():
        return 1
        
    @staticmethod
    def binary(operands, **kwargs):
        opcode = __zero_extend__(bin(spop.opcode()), OPCODE_WIDTH)
        return [__zero_extend__(opcode, BIT_WIDTH, pad_right=True)]
        
    @staticmethod
    def hex(operands, **kwargs):
        return [__bin2hex__(instr) for instr in spop.binary(operands, **kwargs)]
        

class la(Instruction):
    """la $RX, label
    
    Equivalent to:
    jalr $RX, $RX       - to get current pc
    lw $RX, 2($RX)      - to load the word hardcoded_label_value
    beq $zero, $zero, 1 - to jump to the next instruction after label value
    .fill distance_to_label
    """
    
    @staticmethod
    def opcode():
        return None
        
    @staticmethod
    def size():
        return 4
        
    @staticmethod
    def binary(operands, **kwargs):
        assert('pc' in kwargs)  # Sanity check

        pc = kwargs['pc']
        
        match = __RE_LA__.match(operands)
        if match is None:
            raise RuntimeError("Operands '{}' are in an incorrect format.".format(operands.strip()))
        
        RX = match.group('RX')
        label = match.group('Label')
        
        if RX == '$zero':
            raise RuntimeError("'la' instruction cannot be used with '$zero' register.")
        elif label not in SYMBOL_TABLE:
            raise RuntimeError("Label '{}' cannot be resolved.".format(label))
        
        result = jalr.binary('{0}, {0}'.format(RX))
        result.extend(lw.binary('{0}, 2({0})'.format(RX)))
        result.extend(beq.binary('$zero, $zero, 1', pc=pc+3))
        result.extend(fill.binary(SYMBOL_TABLE[label]))
        
        return result
        
    @staticmethod
    def hex(operands, **kwargs):
        return [__bin2hex__(instr) for instr in la.binary(operands, **kwargs)]


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
        return 1
        
    @staticmethod
    def binary(operands, **kwargs):
        return add.binary('$zero, $zero, $zero')
        
    @staticmethod
    def hex(operands, **kwargs):
        return [__bin2hex__(instr) for instr in noop.binary(operands, **kwargs)]


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
        
        
class halt(Instruction):
    @staticmethod
    def opcode():
        return None
        
    @staticmethod
    def size():
        return 1
        
    @staticmethod
    def binary(operands, **kwargs):
        return spop.binary(operands, **kwargs)
        
    @staticmethod
    def hex(operands, **kwargs):
        return [__bin2hex__(instr) for instr in halt.binary(operands, **kwargs)]
