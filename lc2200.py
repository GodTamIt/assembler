import re

"""lc2200.py: A definition of the LC-2200 architecture."""
__author__ = "Christopher Tam"


# Define the name of the architecture
__name__ = 'LC-2200'

# Define a 32-bit architecture 
BIT_WIDTH = 32
# Define 4-bit opcodes
OPCODE_WIDTH = 4
# Define 4-bit register specifiers
REGISTER_WIDTH = 4

VALID_OPCODES = {
        'add':'r', 
        'neg':'j', 
        'addi':'i', 
        'lw':'i', 
        'sw':'i', 
        'beq':'i', 
        'jalr':'j', 
        'spop':'s',
        'la': 'pseudo',
        'noop': 'pseudo',
        '.word': 'pseudo',
        'halt': 'pseudo'}
    
    
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
        '$ra'   :   15,}
        
# Just an ordered list
# REGISTERS = [
#         '$zero',
#         '$at',
#         '$v0',
#         '$a0',
#         '$a1',
#         '$a2',
#         '$t0',
#         '$t1',
#         '$t2',
#         '$s0',
#         '$s1',
#         '$s2',
#         '$k0',
#         '$sp',
#         '$fp',
#         '$ra']


SYMBOL_TABLE = {}


# Public Functions
def is_blank(line):
    return __RE_BLANK__.match(line) is not None
    
def get_parts(line):
    m = __RE_PARTS__.match(line)
    try:
        return m.group('Label'), m.group('Opcode'), m.group('Operands')
    except:
        return None


# Private Variables
__OFFSET_SIZE__ = BIT_WIDTH - OPCODE_WIDTH - (REGISTER_WIDTH * 2)
assert(__OFFSET_SIZE__ > 0)  # Sanity check

__RE_BLANK__ = re.compile(r'^\s*(!.*)?$')
__RE_PARTS__ = re.compile(r'^\s*((?P<Label>\w+):)?\s*((?P<Opcode>\.?[\w]+)(?P<Operands>[^!]*))?(!.*)?')
__RE_HEX__ = re.compile(r'0x[A-z0-9]*')
__RE_R__ = re.compile(r'^\s*(?P<RX>\$\w+?)\s*,\s*(?P<RY>\$\w+?)\s*,\s*(?P<RZ>\$\w+?)\s*$')
__RE_J__ = re.compile(r'^\s*(?P<RX>\$\w+?)\s*,\s*(?P<RY>\$\w+?)\s*$')
__RE_I__ = re.compile(r'^\s*(?P<RX>\$\w+?)\s*,\s*(?P<RY>\$\w+?)\s*,\s*(?P<Offset>\S+?)\s*$')

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

def __parse_offset__(offset, pc=None):
    bin_offset = None
    
    if type(offset) is str:
        if pc is not None and offset in SYMBOL_TABLE:
            offset = SYMBOL_TABLE[offset] - (pc + 1)
        elif offset.startswith('0x'):
            try:
                bin_offset = __hex2bin__(offset)
            except:
                raise RuntimeError("Offset '{}' is not in a valid hexadecimal format.".format(offset))
                
            if len(bin_offset) > __OFFSET_SIZE__:
                raise RuntimeError("Offset '{}' is too large for {}.".format(offset, __name__))
                
            bin_offset = __zero_extend__(bin_offset, __OFFSET_SIZE__)
        elif offset.startswith('0b'):
            try:
                bin_offset = bin(int(offset))
            except:
                raise RuntimeError("Offset '{}' is not in a valid binary format.".format(offset))
                
            if len(bin_offset) > __OFFSET_SIZE__:
                raise RuntimeError("Offset '{}' is too large for {}.".format(offset, __name__))
                
            bin_offset = __zero_extend__(bin_offset, __OFFSET_SIZE__)
            
    if bin_offset is None:
        try:
            offset = int(offset)
        except:
            raise RuntimeError("Offset '{}' is not in a decimal valid format.".format(offset))
            
        bound = 2**(__OFFSET_SIZE__ - 1)
        if offset < -bound or offset >= bound:
            raise RuntimeError("Offset '{}' is too large for {}.".format(offset, __name__))
        
        bin_offset = __dec2bin__(offset, __OFFSET_SIZE__)
    
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

def __parse_i__(operands, is_mem, pc=None):
    # Define result
    result_list = []
    
    match = __RE_I__.match(operands)
    
    if match is None:
        raise RuntimeError("Operands '{}' are in an incorrect format.".format(operands.strip()))
    
    for op in (match.group('RX'), match.group('RY')):
        if op in REGISTERS:
            result_list.append(__zero_extend__(bin(REGISTERS[op]), REGISTER_WIDTH))
        else:
            raise RuntimeError("Register identifier '{}' is not valid in {}.".format(op, __name__))
            
    result_list.append(__parse_offset__(match.group('Offset'), pc))
    
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
    def binary(operands):
        """Assemble the instruction into binary form.
        
        Keyword arguments:
        operands -- a string representation of the operands of the instruction.
        
        Returns an iterable representation of the binary instruction(s).
        """
        raise NotImplementedError()
        
    @staticmethod
    def hex(operands):
        """Assemble the instruction into hexadecimal form.
        
        Keyword arguments:
        operands -- a string representation of the operands of the instruction.
        
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
    def binary(operands):
        opcode = __zero_extend__(bin(add.opcode()), OPCODE_WIDTH)
        operands = __parse_r__(operands)
        return __zero_extend__(opcode + operands, BIT_WIDTH, pad_right=True)
        
    @staticmethod
    def hex(operands):
        return [__bin2hex__(neg.binary(operands))]

class neg(Instruction):
    @staticmethod
    def opcode():
        return 1
        
    @staticmethod
    def size():
        return 1
        
    @staticmethod
    def binary(operands):
        opcode = __zero_extend__(bin(neg.opcode()), OPCODE_WIDTH)
        operands = __parse_j__(operands)
        return [__zero_extend__(opcode + operands, BIT_WIDTH, pad_right=True)]
        
    @staticmethod
    def hex(operands):
        return [__bin2hex__(neg.binary(operands))]


class addi(Instruction):
    @staticmethod
    def opcode():
        return 2
        
    @staticmethod
    def size():
        return 1
        
    @staticmethod
    def binary(operands):
        opcode = __zero_extend__(bin(addi.opcode()), OPCODE_WIDTH)
        operands = __parse_i__(operands)
        return [__zero_extend__(opcode + operands, BIT_WIDTH, pad_right=True)]
        
    @staticmethod
    def hex(operands):
        return [__bin2hex__(addi.binary(operands))]
        

class lw(Instruction):
    @staticmethod
    def opcode():
        return 3
        
    @staticmethod
    def size():
        return 1
        
    @staticmethod
    def binary(operands):
        opcode = __zero_extend__(bin(addi.opcode()), OPCODE_WIDTH)
        operands = __parse_i__(operands)
        return __zero_extend__(opcode + operands, BIT_WIDTH, True)
        
    @staticmethod
    def hex(operands):
        return __bin2hex__(addi.binary(operands))


# BINARY_OPCODES = {'add':'000',
#         'neg':'001',
#         'addi':'010',
#         'lw':'011',
#         'sw':'100',
#         'beq':'101',
#         'jalr':'110',
#         'spop':'111'}
# BINARY_REGISTERS = {'zero':'0000', 'at':'0001', 'v0':'0010', 'a0':'0011', 
#         'a1':'0100', 'a2':'0101', 't0':'0110', 't1':'0111', 
#         't2':'1000', 's0':'1001', 's1':'1010', 's2':'1011',
#         'k0':'1100', 'sp':'1101', 'fp':'1110', 'ra':'1111'}