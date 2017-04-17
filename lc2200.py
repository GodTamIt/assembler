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

VALID_PARAMS = {}

PARAMS = {}


# Private Variables
OFFSET_SIZE = BIT_WIDTH - OPCODE_WIDTH - (REGISTER_WIDTH * 2)
assert(OFFSET_SIZE > 0) # Sanity check

UNUSED_SIZE = BIT_WIDTH - OPCODE_WIDTH - (REGISTER_WIDTH * 3)
assert(UNUSED_SIZE > 0) # Sanity check

SHF_IMM_SIZE = 5

SHF_UNUSED_SIZE = OFFSET_SIZE - SHF_IMM_SIZE - 2
assert(SHF_UNUSED_SIZE > 0) # Sanity check


RE_BLANK = re.compile(r'^\s*(!.*)?$')
RE_PARTS = re.compile(r'^\s*((?P<Label>\w+):)?\s*((?P<Opcode>\.?[\w]+)(?P<Operands>[^!]*))?(!.*)?')


def zero_extend(binary, target, pad_right=False):
    if binary.startswith('0b'):
        binary = binary[2:]
    
    zeros = '0' * (target - len(binary))
    if pad_right:
        return binary + zeros
    else:
        return zeros + binary
    
def sign_extend(binary, target):
    if binary.startswith('0b'):
        binary = binary[2:]

    return binary[0] * (target - len(binary)) + binary
    
def bin2hex(binary):
    return '%0*X' % ((len(binary) + 3) // 4, int(binary, 2))
    
def hex2bin(hexadecimal):
    return bin(int(hexadecimal, 16))[2:]
    
def dec2bin(num, bits):
    """Compute the 2's complement binary of an int value."""
    return format(num if num >= 0 else (1 << bits) + num, '0{}b'.format(bits))

def parse_value(offset, size, pc=None, unsigned=False):
    bin_offset = None
    
    if type(offset) is str:
        if pc is not None and offset in SYMBOL_TABLE:
            offset = SYMBOL_TABLE[offset] - (pc + 1)
        elif offset.startswith('0x'):
            try:
                bin_offset = hex2bin(offset)
            except:
                raise RuntimeError("'{}' is not in a valid hexadecimal format.".format(offset))
                
            if len(bin_offset) > size:
                raise RuntimeError("'{}' is too large for {}.".format(offset, __name__))
                
            bin_offset = zero_extend(bin_offset, size)
        elif offset.startswith('0b'):
            try:
                bin_offset = bin(int(offset))
            except:
                raise RuntimeError("'{}' is not in a valid binary format.".format(offset))
                
            if len(bin_offset) > size:
                raise RuntimeError("'{}' is too large for {}.".format(offset, __name__))
                
            bin_offset = zero_extend(bin_offset, size)
            
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
            
        bin_offset = dec2bin(offset, size)
    
    return bin_offset



class Instruction:
    """
    This is the base class that all implementations of instructions must override.
    """

    @classmethod
    def opcode(cls):
        """Return the operation code for the given instruction as an integer."""
        raise NotImplementedError()

    def __init__(self, operands, pc, instruction):
        self.__operands = operands
        self.bin_operands = self.parse_operands(operands, pc, instruction)
        self.__pc = pc
        self.__instruction = instruction

    @classmethod
    def create(cls, operands, pc, instruction):
        """Generates a list of Instruction(s) for the given operands."""
        raise NotImplementedError()

    @classmethod
    def pc(cls, pc, **kwargs):
        """Return the new PC after assembling the given instruction"""
        # By default, return pc + 1
        return pc + 1

    @classmethod
    def parse_operands(cls, operands, pc, instruction):
        return ''

    def binary(self):
        """Assemble the instruction into binary form.
        
        Returns a string representation of the binary instruction.
        """
        raise NotImplementedError()
        
    def hex(self):
        """Assemble the instruction into binary form.
        
        Returns a string representation of the binary instruction.
        """
        return bin2hex(self.binary())


class RInstruction(Instruction):
    """
    The base class for R-type instructions.
    """

    __RE_R = re.compile(r'^\s*(?P<RX>\$\w+?)\s*,\s*(?P<RY>\$\w+?)\s*,\s*(?P<RZ>\$\w+?)\s*$')

    @classmethod
    def create(cls, operands, pc, instruction):
        return [cls(operands, pc, instruction)]

    @classmethod
    def parse_operands(cls, operands, pc, instruction):
        # Define result
        result_list = []
        
        match = cls.__RE_R.match(operands)
        
        if match is None:
            raise RuntimeError("Operands '{}' are in an incorrect format.".format(operands.strip()))
        
        for op in (match.group('RX'), match.group('RY'), match.group('RZ')):
            if op in REGISTERS:
                result_list.append(zero_extend(bin(REGISTERS[op])[2:], REGISTER_WIDTH))
            else:
                raise RuntimeError("Register identifier '{}' is not valid in {}.".format(op, __name__))

        # Insert unused bits
        result_list.insert(2, '0' * UNUSED_SIZE)
        
        return ''.join(result_list)

    def binary(self):
        return zero_extend(bin(self.opcode()), OPCODE_WIDTH) + self.bin_operands


class IInstruction(Instruction):
    """
    The base class for I-type instructions.
    """

    __RE_I = re.compile(r'^\s*(?P<RX>\$\w+?)\s*,\s*(?P<RY>\$\w+?)\s*,\s*(?P<Offset>\S+?)\s*$')
    __RE_OFF = re.compile(r'^\s*(?P<RX>\$\w+?)\s*,\s*(?P<Offset>\S+?)\s*\((?P<RY>\$\w+?)\)\s*$')

    @classmethod
    def is_offset_style(cls):
        raise NotImplementedError()

    @classmethod
    def parse_operands(cls, operands, pc, instruction):
        # Define result
        result_list = []

        match = cls.__RE_OFF.match(operands) if cls.is_offset_style() else cls.__RE_I.match(operands)

        if match is None:
            raise RuntimeError("Operands '{}' are in an incorrect format.".format(operands.strip()))

        for op in (match.group('RX'), match.group('RY')):
            if op in REGISTERS:
                result_list.append(zero_extend(bin(REGISTERS[op]), REGISTER_WIDTH))
            else:
                raise RuntimeError("Register identifier '{}' is not valid in {}.".format(op, __name__))

        result_list.append(parse_value(match.group('Offset'), OFFSET_SIZE, pc))

        return ''.join(result_list)

    def binary(self):
        return zero_extend(bin(self.opcode()), OPCODE_WIDTH) + self.bin_operands


class BRInstruction(IInstruction):
    """
    The base class for branch versions of I-type instructions.
    """

    @classmethod
    def is_offset_style(cls):
        return False

    @classmethod
    def create(cls, operands, pc, instruction):
        return [cls(operands, pc, instruction)]

    def binary(self):
        padded_opcode = zero_extend(bin(self.opcode()), OPCODE_WIDTH)
        return zero_extend(padded_opcode + self.bin_operands, BIT_WIDTH, pad_right=True)




class add(RInstruction):
    @classmethod
    def opcode(cls):
        return 0


class neg(RInstruction):
    @classmethod
    def opcode(cls):
        return 1


class addi(IInstruction):
    @classmethod
    def opcode(cls):
        return 2

    @classmethod
    def is_offset_style(cls):
        return False

    @classmethod
    def create(cls, operands, pc, instruction):
        return [cls(operands, None, instruction)]


class lw(IInstruction):
    @classmethod
    def opcode(cls):
        return 3

    @classmethod
    def is_offset_style(cls):
        return True

    @classmethod
    def create(cls, operands, pc, instruction):
        return [cls(operands, None, instruction)]


class sw(IInstruction):
    @classmethod
    def opcode(cls):
        return 4

    @classmethod
    def is_offset_style(cls):
        return True

    @classmethod
    def create(cls, operands, pc, instruction):
        return [cls(operands, None, instruction)]


class beq(BRInstruction):
    @classmethod
    def opcode(cls):
        return 5


class jalr(Instruction):
    __RE_JALR = re.compile(r'^\s*(?P<AT>\$\w+?)\s*,\s*(?P<RA>\$\w+?)\s*$')

    @classmethod
    def opcode(cls):
        return 6

    @classmethod
    def create(cls, operands, pc, instruction):
        return [cls(operands, pc, instruction)]
        
    @classmethod
    def pc(cls, pc, **kwargs):
        return pc + 1

    @classmethod
    def parse_operands(cls, operands, pc, instruction):
        # Define result
        result_list = []
        
        match = cls.__RE_JALR.match(operands)
        
        if match is None:
            raise RuntimeError("Operands '{}' are in an incorrect format.".format(operands.strip()))

        for op in (match.group('RA'), match.group('AT')):
            if op in REGISTERS:
                result_list.append(zero_extend(bin(REGISTERS[op]), REGISTER_WIDTH))
            else:
                raise RuntimeError("Register identifier '{}' is not valid in {}.".format(op, __name__))
                
        return ''.join(result_list)

    def binary(self):
        padded_opcode = zero_extend(bin(self.opcode()), OPCODE_WIDTH)
        return zero_extend(padded_opcode + self.bin_operands, BIT_WIDTH, pad_right=True)


class spop(Instruction):
    @classmethod
    def opcode(cls):
        return 7

    @classmethod
    def create(cls, operands, pc, instruction):
        return [cls(operands, pc, instruction)]

    def binary(self):
        padded_opcode = zero_extend(bin(self.opcode()), OPCODE_WIDTH)
        return zero_extend(padded_opcode, BIT_WIDTH, pad_right=True)


class la(Instruction):
    """la $RX, label
    
    Equivalent to:
    jalr $RX, $RX       - to get current pc
    lw $RX, 2($RX)      - to load the word hardcoded_label_value
    beq $zero, $zero, 1 - to jump to the next instruction after label value
    .fill hardcoded_label_value
    """

    __RE_LA = re.compile(r'^\s*(?P<RX>\$\w+?)\s*,\s*(?P<Label>\w+?)\s*$')

    @classmethod
    def opcode(cls):
        return None

    @classmethod
    def create(cls, operands, pc, instruction):
        match = cls.__RE_LA.match(operands)
        if match is None:
            raise RuntimeError("Operands '{}' are in an incorrect format.".format(operands.strip()))
        
        RX = match.group('RX')
        label = match.group('Label')
        
        if RX == '$zero':
            raise RuntimeError("'la' instruction cannot be used with '$zero' register.")
        elif label not in SYMBOL_TABLE:
            raise RuntimeError("Label '{}' cannot be resolved.".format(label))

        result = []

        result.append(jalr.create(operands='{0}, {0}'.format(RX), pc=pc+1, instruction='jalr'))
        result.append(lw.create(operands='{0}, 2({0}', pc=pc+2, instruction='lw').format(RX))
        result.append(beq.create(operands='$zero, $zero, 1', pc=pc+3, instruction='beq'))
        result.append(fill.binary(operands=SYMBOL_TABLE[label], pc=pc+4, instruction='.fill'))

        return result

    @classmethod
    def pc(cls, pc, **kwargs):
        return pc + 4


class halt(spop):
    @classmethod
    def create(cls, operands, pc, instruction):
        return [cls('', pc, instruction)]


class noop(add):
    """noop
    
    Equivalent to:
    add $zero, $zero, $zero
    """

    @classmethod
    def create(cls, operands, pc, instruction):
        return [cls('$zero, $zero, $zero', pc, instruction)]


class ret(jalr):
    """ret
    
    Equivalent to:
    jalr $ra, $zero
    """

    @classmethod
    def create(cls, operands, pc, instruction):
        return [cls('$ra, $zero', pc, instruction)]


class fill(Instruction):
    @classmethod
    def opcode(cls):
        return None
        
    @classmethod
    def create(cls, operands, pc, instruction):
        return [cls(operands, pc, instruction)]

    @classmethod
    def parse_operands(cls, operands, pc, instruction):
        if type(operands) is str:
            operands = operands.strip()

        return parse_value(operands, BIT_WIDTH)
        
    def binary(self):
        return self.bin_operands




# Functions expected by the assembler
def receive_params(value_table):
    if not value_table:
        return

    for key in value_table:
        key = key.lower()
        if key not in VALID_PARAMS:
            raise RuntimeError('{} is not a valid custom parameter.')
        
        if VALID_PARAMS[key]:
            try:
                PARAMS[key] = VALID_PARAMS[key](value_table[key])
            except:
                raise RuntimeError('{} parameter is not of the valid {}.'.format(key, VALID_PARAMS[key]))


def is_blank(line):
    """Return whether a line is blank and not an instruction."""
    return RE_BLANK.match(line) is not None
    
def get_parts(line):
    """Break down an instruction into 3 parts: Label, Opcode, Operand"""
    m = RE_PARTS.match(line)
    try:
        return m.group('Label'), m.group('Opcode'), m.group('Operands')
    except:
        return None

def instruction_class(name):
    """Translate a given instruction name to its corresponding class name."""
    return ALIASES.get(name, name)

def validate_pc(pc):
    """Returns or modifies the PC to a permitted value, if possible. Throws an error if the PC is invalid."""
    if pc >= 2**BIT_WIDTH:
        raise RuntimeError("PC value {} is too large for {} bits.".format(pc, BIT_WIDTH))

    return pc

def output_generator(assembled_dict, output_format='binary'):
    """Returns a generator that creates output from {pc : assembly}-formatted dictionary."""
    pc = 0
    count = 0

    while count < len(assembled_dict):
        instr = None
        if pc in assembled_dict:
            instr = assembled_dict[pc]
            pc += 1
            count += 1
        else:
            instr = noop.create('', pc, 'noop')

            pc = instr.pc(pc)

        yield getattr(instr, output_format)()