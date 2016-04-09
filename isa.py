import re

"""isa.py: A definition of the LC-2200 architecture."""
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
__RE_BLANK__ = re.compile(r'^\s*(!.*)?$')
__RE_PARTS__ = re.compile(r'^\s*((?P<Label>\w+):)?\s*((?P<Opcode>\.?[\w]+)(?P<Operands>[^!]*))?(!.*)?')
__RE_R__ = re.compile(r'^\s*(?P<RX>\$\w+?)\s*,\s*(?P<RY>\$\w+?)\s*,\s*(?P<RZ>\$\w+?)\s*$')
__RE_J__ = re.compile(r'^\s*(?P<RX>\$\w+?)\s*,\s*(?P<RY>\$\w+?)\s*$')
__RE_I__ = re.compile(r'^\s*(?P<RX>\$\w+?)\s*,\s*(?P<RY>\$\w+?)\s*,\s*(?P<Offset>\S+?)\s*$')

# Private Functions
def __zero_extend__(binary, target, pad_right=False):
    zeros = '0' * (target - len(binary))
    if pad_right:
        return binary + zeros
    else:
        return zeros + binary
    
def __sign_extend__(binary, target):
    return binary[0] * (target - len(binary)) + binary
    
def __bin2hex__(binary):
    return '%0*X' % ((len(binary) + 3) // 4, int(binary, 2))

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

def __parse_i__(operands):
    # Define result
    result_list = []
    
    match = __RE_I__.match(operands)
    
    if match is None:
        raise RuntimeError("Operands '{}' are in an incorrect format.".format(operands.strip()))
    
    for op in (match.group('RX'), match.group('RY')):
        if op in REGISTERS:
            result_list.append(__zero_extend__(bin(REGISTERS[op])[2:], REGISTER_WIDTH))
        else:
            raise RuntimeError("Register identifier '{}' is not valid in {}.".format(op, __name__))
            
    # TODO        
    
    return ''.join(result_list)

def __parse_j__(operands):
    # Define result
    result_list = []
    
    match = __RE_J__.match(operands)
    
    if match is None:
        raise RuntimeError("Operands '{}' are in an incorrect format.".format(operands.strip()))
    
    for op in (match.group('RX'), match.group('RY')):
        if op in REGISTERS:
            result_list.append(__zero_extend__(bin(REGISTERS[op])[2:], REGISTER_WIDTH))
        else:
            raise RuntimeError("Register identifier '{}' is not valid in {}.".format(op, __name__))
            
    return ''.join(result_list)
    

# Instruction Definitions
class Instruction:
    """
    This is the base class that all implementations of instructions must override.
    """
    @staticmethod
    def opcode():
        raise NotImplementedError()
    
    @staticmethod
    def size():
        raise NotImplementedError()
        
    @staticmethod
    def binary(operands):
        raise NotImplementedError()
        
    @staticmethod
    def hex(operands):
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
        opcode = __zero_extend__(bin(add.opcode())[2:], OPCODE_WIDTH)
        operands = __parse_r__(operands)
        return __zero_extend__(opcode + operands, BIT_WIDTH, True)
        
    @staticmethod
    def hex(operands):
        return __bin2hex__(neg.binary(operands))

class neg(Instruction):
    @staticmethod
    def opcode():
        return 1
        
    @staticmethod
    def size():
        return 1
        
    @staticmethod
    def binary(operands):
        opcode = __zero_extend__(bin(neg.opcode())[2:], OPCODE_WIDTH)
        operands = __parse_j__(operands)
        return __zero_extend__(opcode + operands, BIT_WIDTH, True)
        
    @staticmethod
    def hex(operands):
        return __bin2hex__(neg.binary(operands))


class addi(Instruction):
    @staticmethod
    def opcode():
        return 2
        
    @staticmethod
    def size():
        return 1
        
    @staticmethod
    def binary(operands):
        opcode = __zero_extend__(bin(addi.opcode())[2:], OPCODE_WIDTH)
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