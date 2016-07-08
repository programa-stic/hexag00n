from __future__ import (absolute_import, division,
                        print_function, unicode_literals)

from builtins import (ascii, bytes, chr, dict, filter, hex, input,
                      int, map, next, oct, open, pow, range, round,
                      str, super, zip)
         
import inspect
import re
import pickle
import os

DATA_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), './data/')
# TODO: Is this the correct way to reference a package_data file?

INST_DEF_PATH = os.path.join(DATA_PATH, 'instruction_definitions.pkl')
INST_TEMPL_PATH = os.path.join(DATA_PATH, 'instruction_templates.pkl')
FACTORIAL_EXAMPLE_ELF = os.path.join(DATA_PATH, 'factorial_example.elf')

# Hexagon instruction size in bytes.
INST_SIZE = 4

# Maximum size of an Hexagon packet in bytes. Each packet has at most 4 instructions.
PACKET_MAX_SIZE = 4 * INST_SIZE

hex_digit = r"[\dA-Fa-f]"

class InstructionDefinition(object):
    """Definition of an instruction (like the manual): syntax, encoding, and beahvior.

    Instructions obtained by the importer (either from the manual or the objdump
    headers). It has the minimal processing, only on the instruction encoding, converted
    to `InstructionEncoding` (it has no use as a string), the major work is done in
    the `InstructionTemplate` through the decoder.

    The behavior attribute is optional, because the parser still doesn't support many of
    the manual's behavior strings.

    Attributes:
        syntax (str)
        encoding (InstructionEncoding)
        behavior (str)

    """
    __slots__ = ['syntax', 'encoding', 'behavior']
    
    def __init__(self, syntax, encoding):
        self.syntax = syntax
        self.encoding = InstructionEncoding(encoding)
        self.behavior = ''


class InstructionTemplate(object):
    """Definition of the instruction with the maximum processing done before being used for disassembly.

    Created by the decoder from an `InstructionDefinition`.
    All the major attributes of the instruction are processed and
    stored here, e.g., operands, duplex, branches, tokens, etc.

    Attributes:
        encoding (InstructionEncoding): Hexagon instruction encoding, as seen in the manual.
        syntax (str): Hexagon instruction syntax, as seen in the manual, e.g. ``Rd=add(Rs,#s16)``.
        operands (Dict[str, InstructionOperand]): Operands (registers or immediates) indexed by their
            respective field char, e.g., operands['d'] -> InstructionOperand(Rd).
        mult_inst (bool): Has more than one atomic instruction, i.e., has a ';' in the syntax.
        is_duplex (bool): Indicates if this is a duplex instruction.
        imm_ops (List[ImmediateTemplate]): List of the instruction register operand templates.
        reg_ops (List[RegisterTemplate]): List of the instruction immediate operand templates.
        branch (Optional[TemplateBranch]): If not None, has the branch being performed by the
            instruction, identified by the encoding analyzing the instruction syntax and not
            its behavior (as it should).
        behavior (str): Hexagon instruction behavior, as seen in the manual, e.g. ``Rd=Rs+#s;``.
        imm_ext_op (Optional[ImmediateTemplate]): "Pointer" to the immediate operand that can
            be extended in the instruction. It is just a hint for the disassembler, to let it
            know what immediate operand can be the target of a constant extension. "Pointer"
            here means that it has one of the imm. ops. in the `imm_ops` list.
        tokens (List[TemplateToken]): List of strings representing the tokenized behavior, where
            splits are done in the cases where part of the syntax can be linked to an operand,
            see `HexagonInstructionDecoder.tokenize_syntax`.

    """
    __slots__ = ['encoding', 'syntax', 'operands', 'mult_inst',
                 'is_duplex', 'imm_ops', 'reg_ops', 'branch', 'behavior',
                 'imm_ext_op', 'tokens']


    register_operand_field_chars = ['N', 't', 'd', 'x', 'u', 'e', 'y', 'v', 's']
    # Seen on the manual
    
    # Added from the objdump headers, but not in the manual
    register_operand_field_chars.extend(['f', 'z'])
    
    immediate_operand_field_chars = ['i', 'I']

    other_field_chars = ['-',  'P', 'E']
    # 'E' added from the objdump header encodings (not in the manual)

    field_chars =   register_operand_field_chars + \
                    immediate_operand_field_chars + \
                    other_field_chars
    # TODO: move all field char definitions inside `generate_operand` or in `common.py`.

    def __init__(self, inst_def):
        
        self.encoding = inst_def.encoding
        self.syntax = standarize_syntax_objdump(inst_def.syntax)
        self.behavior = inst_def.behavior
        # TODO: Create an ``InstructionField`` that groups these 3 attributes.

        self.imm_ops = []
        self.reg_ops = []

        self.operands = {}
        # Contains the same info as imm_ops + reg_ops, only used inside
        # `generate_instruction_operands`.
        # TODO: Remove this attribute.

        self.branch = None
        self.imm_ext_op = None
        self.tokens = []
        
        self.mult_inst = (';' in self.syntax)

        self.is_duplex = (self.encoding.text[16:18] == '00')
        # PP (parity bits) set to '00'
        
        for c in self.encoding.fields:
            self.generate_operand(c)
    
    # C: char, ie: inst encoding
    def generate_operand(self, c):
        """Generate an operand from an instruction field.

        Args:
            c (str): Field char.

        Returns:
            None: the information is added to `reg_ops`/`imm_ops` and `operands`
                of the same InstructionTemplate.

        """

        if c not in InstructionTemplate.field_chars:
            raise UnexpectedException("Field char {:s} not recognized.".format(c))

        if c in self.register_operand_field_chars:
            reg = self.match_register_in_syntax(self.syntax, c)
            if reg:
                self.operands[c] = reg
                self.reg_ops.append(reg)

                return

        if c in self.immediate_operand_field_chars:
            imm = self.match_immediate_char_in_syntax(self.syntax, c)
            if imm:
                self.operands[c] = imm
                self.imm_ops.append(imm)

                return

        # There is a pretty similar structure in both processings.
        # TODO: Can this be abstracted to a more general function?

        if c == 'N':
            
            # 'N' operand, it indicates an optional behavior in the instruction (which doesn't happen often).
            # TODO: Handle this special operand.
            return

            # Possible solution:
            
            # m = re.search(r"(\[:<<N\])", self.syntax)
            # if m:
            #     self.operands[c].name = m.group(1)
            #     self.operands[c].syntax_pos = (m.start(1), m.end(1))
            #     # print "Found N: " + m.group(1)
            #     return


        # If it gets here there's an unforeseen field char that was not processed correctly.

        raise UnexpectedException("Field char {:s} not processed correctly.".format(c))

    def match_register_in_syntax(self, syntax, reg_char):
        """Find a register operand in the syntax with a specified field char.

        Args:
            syntax (str): Instruction syntax.
            reg_char (str): Field char (str of len 1) used in the instruction encoding to
                represent a field that holds the value for a register operand.

        Returns:
            Optional[RegisterTemplate]: if found, None otherwise.

        TODO:
            * Check other possible registers, Mx for example.

        """

        # Match registers, first generic ones (Rx), then predicates (Px)

        reg_templates = [
            r"(R" + reg_char + r"{1,2})",
             # {1,2}: it can be a double register (e.g. Rdd).

             r"(P" + reg_char + r")",
             r"(N" + reg_char + r".new)",
             r"(M" + reg_char + r")",
             r"(C" + reg_char + r")",

             # Added from the objdump headers, but not in the manual.

             r"(G" + reg_char + r")",
             r"(S" + reg_char + r")",
        ]
        
        for rt in reg_templates: # type: str

            m = re.search(rt, syntax)

            if m:
                return RegisterTemplate(m.group(1))
        
        return None

    def match_immediate_char_in_syntax(self, syntax, imm_char):
        """Find an immediate operand in the syntax with a specified field char.

        Args:
            syntax (str): Instruction syntax.
            imm_char (str): Field char (str of len 1) used in the instruction encoding to
                represent a field that holds the value for an immediate operand.

        Returns:
            Optional[ImmediateTemplate]: if found, None otherwise.

        """
        if imm_char == 'i':
            imm_chars = ['u', 's', 'm', 'r']

        elif imm_char == 'I':
            imm_chars = ['U', 'S', 'M', 'R']
            # TODO: Use list comprehensions.

        else:
            raise UnexpectedException()
        
        for ic in imm_chars: # type: str

            m = re.search(r"(#" + ic + r"\d{1,2})" + r"(:\d)?", syntax)
            # E.g., ``#s16:2``, the optional ``:2`` indicates a scaled immediate.
            # TODO: Improve readabilty of this regex.

            if m:
                imm_syntax = m.group(1)
                scale_factor = 0

                if m.group(2):
                    imm_syntax += m.group(2)
                    scale_factor = int(m.group(2)[1])
                    # ``[1]``: used to skip the ':' in the syntax.
                
                return ImmediateTemplate(imm_syntax, scale_factor)
        
        return None

# Custom exceptions to avoid the use of the base Exception class.

class OutOfLinesException(Exception):
    pass
    # TODO: Is this exception being used?
    
class UnexpectedException(Exception):

    def __init__(self, message = ''):
        super(UnexpectedException, self).__init__(message)

class UnknownInstructionException(Exception):

    def __init__(self, message = ''):
        super(UnknownInstructionException, self).__init__(message)

class UnknownBehaviorException(Exception):
    
    def __init__(self, message = ''):
        super(UnknownBehaviorException, self).__init__(message)

class InstructionEncoding(object):
    """Hexagon instruction encoding.

    Attributes:
        text (str): encoding chars, without spaces, of len 32, each char represents one bit of the
            instruction, e.g., the encoding of ``Rd=add(Rs,#s16)`` is ``1011iiiiiiisssssPPiiiiiiiiiddddd``,
            ``text[0]`` corresponds to bit 31 and ``text[31]`` to bit 0 (LSB) of the encoding.
        mask (int): resulting from setting to 1's all the instruction defining bits, used in the
            disassembly to determine the type of an instruction.
        value (int): resulting from extracting only the instruction defining bits, used in conjunction with
            the mask to determine the type of an instruction.
        fields (Dict[str, EncodingField]): instruction encoding fields, indexed by the field char,
            e.g. fields['d'] -> EncodingField(Rd).

    TODOs:
        * Change `text` attribute's name, so as not to be confused with an instruction text.
        * Fields is a redundant attribute, because the encodings fields are contained
            in the operands dict. key (of the instruction template),
            but it's clearer this way. Should it be eliminated?

    """
    __slots__ = ['text', 'value', 'mask', 'fields']

    def __init__(self, text):

        if len(text) != 32:
            raise UnexpectedException('There has been a problem during the instruction definition import process.')

        # TODO: Check also `text` for spaces.

        # TODO: check that ICLASS bits (31:28 and 31:29,13 for duplex) in `text` are always defined to 0/1.

        self.text = text
        
        self.fields = {}

        self.generate_mask_and_value()
        self.generate_fields()
    
    def generate_mask_and_value(self):
        """Generate the mask and value of the instruction encoding, from its text (str).

        There are no Args nor Return values, everything is done manipulating the
        object attributes: the input would be `self.text` and the output `self.mask`
        and `self.value`.

        """
        self.mask = 0
        self.value = 0
        
        for text_pos in range(32):

            mask_pos = 31 - text_pos
            # The orders of mask bits (int) and text bits (str) are reversed.

            if self.text[text_pos] in ['0', '1']:
                self.mask |= (1 << mask_pos)
                self.value |= int(self.text[text_pos]) << mask_pos

    def generate_fields(self):
        """Generate instruction fields of the instruction encoding, from its text (str).

        Parse everything else that's not a instruction defining bit (0/1), like the ICLASS
        bits, and generate the corresponding fields from each different spotted char.
        The other type of chars ignored (besides 0/1) are '-' (irrelevant bit)
        and 'P' (parse bit).

        The fields created (EncodingField) do not differentiate between immediate or register,
        they are just a bit field at this stage.

        The generation of each field mask is pretty straight forward, but the process
        has been complicated with the fact that the generated mask is checked to see if
        bits are consecutive (no_mask_split), for performance reasons. See `EncodingField`
        description.

        There are no Args nor Return values, everything is done manipulating the
        object attributes: the input would be `self.text` and the output `self.fields`.

        TODOs:
            * Rethink this explanation. 'P' is a valid field, but I'm skipping it because it
                won't be a valid imm. o reg. operand. So even though this encoding fields
                are just bits their ultimate use will be for operands.

            * Use the terms "specific fields" (from "Instruction-specific fields") and
                Common fields (defined in section 10.2 of the manual). ICLASS and parse
                bits (common fields) are the ones I'm ignoring.

            * The rationale behind the `no_mask_split` is split between here and
                `EncodingField`. Unifiy.

            * Avoid skipping any field here, create all the bit fields from the instruction,
                and then skip them during reg./imm. ops. creation, to simplify the logic
                here (less coupling, this function is doing -or knowing- more than it should).

        """
        field_last_seen_pos = {} # type: Dict[str, int])
        # Used to detect a mask split.
        # TODO: Elaborate on this.
        
        for text_pos in range(32):

            mask_pos = 31 - text_pos
            # The orders of mask bits (int) and text bits (str) are reversed.

            if mask_pos in [14, 15]: # skip 'P', parse bits
                continue
                # TODO: Remove this check when this function is permitted to parse all fields
                # (and discard the P field later when generating the operands).

            c = self.text[text_pos]

            if c not in ['0', '1', '-']:
                # TODO: Change to a continue clause, to remove all the following indentation.
                
                if c not in self.fields:
                    # Char seen for the first time, create a new field.

                    self.fields[c] = EncodingField()
                    self.fields[c].no_mask_split = True
                    field_last_seen_pos[c] = (-1)
                    # (-1): used to indicate that it's a new field, and there's
                    # no last seen char before this one.
                    
                self.fields[c].mask |= (1 << mask_pos)
                self.fields[c].mask_len += 1

                # Detect a split in the field (and if so, reflect it on the mask).

                if field_last_seen_pos[c] != -1:
                    if mask_pos != (field_last_seen_pos[c] - 1): # mask_pos iteration is going ackwards
                        self.fields[c].no_mask_split = False

                field_last_seen_pos[c] = mask_pos

        for c in self.fields:
            self.fields[c].mask_lower_pos = field_last_seen_pos[c]
            # The last seen position in the text (str) of each field is the
            # lowest position in the mask (int), as their orders are reversed.


class EncodingField(object):
    """Hexagon instruction encoding field, as seen in the manual.

    An encoding field can be characterized with only a mask (int) with the 1's set
    to indicate the positions of the field chars in the encoding. E.g., in the encoding
    (str) ``1011iiiiiiisssssPPiiiiiiiiiddddd``, the field ``s5`` would have a mask
    (int) like ``0b00000000000111110000000000000000``.

    This mask is used to later extract the value of the field in the instruction
    being disassembled, which would be used to generate either an immediate or
    register operand.

    This value extraction (bit by bit) can be time consuming. To improve performance,
    and taking advantage of the fact that most encoding fields are unified, (i.e.,
    all their field chars have consecutive order, like the example above), other
    (redundant) attributes are added to the class to reflect this.
    If a field is unified (``no_mask_split`` is True), the field value can
    be extracted just by applying a logical and operation, if the mask is split,
    after the logical and, the extracted bits need to be joined (which is time consumig
    for the disassembly process, as seen in the profiling results).

    Attributes:

        mask (int): resulting from setting to 1's the positions in the instruction encoding
            where the corresponding field char appears.
        mask_len (int): number of times the field char appears on the encoding field (i.e.,
            number of 1's in the mask).
        no_mask_split (bool): indicates whether all the field chars have a consecutive
            bit ordering (i.e., if all the 1's in the mask are together).
        mask_lower_pos (int): lowest bit index in the encoding where the field char is found
            (i.e. position of the first 1 in the mask).

    TODOs:
        * Improve this class explanation, its use is in the disassembler, maybe move
            some of the explanation there (to `extract_and_join_mask_bits` function).

        * Clearly differentiate between bit-by-bit processing vs manipulating all
            bits together (extract bits).

        * Change `mask_lower_pos` to ``field_lower_pos`` or ``field_start_pos``.

        * Change `no_mask_split` to ``mask_split`` and adjust logic, asking
            for ``if not no_mask_split`` is too cumbersome.

    """
    __slots__ = ['mask', 'mask_len', 'no_mask_split', 'mask_lower_pos']

    def __init__(self):
        self.mask = 0
        self.mask_len = 0
        # Used to determine the sign of immediates.
        # TODO: Is mask_len used just for that?

        
class TemplateBranch(object):
    """Hexagon instruction branch.

    Attribute that adds information to the InstructionTemplate, used mainly
    in the IDA processor module to perform branch analysis..

    Attributes:

        type (str): of branch, useful for IDA analysis.
        target (OperandTemplate): operand template (register or immediate) in the instruction
            that contains the target of the branch.
        is_conditional (bool): True if conditional branch (there's an 'if' inside
            the syntax); False otherwise.

    TODOs:

        * Define the branch type inside a class or enum or somewhere unified,
            not as strings, and not inside the class.

        * Comment on each branch type separately, explaining the difference.

        * Change `all_branches` name to ``branch_syntax(es)``.

        * Change `all_branches` name to ``branch_syntax(es)``.

        * Document a branch as the union of hexagon jumps and calls.

        * The branch syntax is used like a regexp pattern, the spaces (added for readability)
            are ignored only if ``re.search`` is called with ``re.X`` argument
            (e.g., as `analyze_branch` does), enforce/specify this.

        * Once the branch types are unified give examples.

    """
    __slots__ = ['target', 'is_conditional', 'type']

    jump_reg_syntax =      r'jumpr (?: :t | :nt)?'  # ``?:`` don't capture group
    jump_imm_syntax =      jump_reg_syntax.replace('jumpr', 'jump')
    call_reg_syntax =      r'callr'
    call_imm_syntax =      call_reg_syntax.replace('callr', 'call')
    dealloc_ret_syntax =   r'dealloc_return'
    all_branches = [jump_reg_syntax, jump_imm_syntax, call_reg_syntax, call_imm_syntax, dealloc_ret_syntax]

    def __init__(self, type):
        self.type = type
        self.target = None
        self.is_conditional = False

class TemplateToken(object):
    """Hexagon instruction template token.

    Used mainly in the IDA processor module, to print some parts of the syntax (tokens)
    in a special manner, matching the strings (`s`) with their corresponding operand (`op`).

    Attributes:

        s (str): token string.
        op (Optional[OperandTemplate]): operand template (if any) that corresponds to the token.

    TODOs:
        * Change `s` name to something more descriptive, maybe also `op`,
            using more than 2 letters is allowed...

    """
    __slots__ = ['s', 'op']

    def __init__(self, s):
        self.s = s
        self.op = None


def bin_str(self, i):
    # TODO: Is this used now?
    s = bin(i)
    s = s[2:] # Remove 0b
    s = s.zfill(32)
    return s


def extract_bits(value, bit_end, bit_start):
    """Extract a value from a bit range.

    Args:
        value (int): Input value from which the bit range is extracted.
        bit_start (int): Index of first bit of the range.
        bit_end (int): Index, inclusive, of the last bit of the range.

    Returns:
        int: extracted value.

    Raises:
        UnexpectedException: If `bit_end` is less than `bit_start`.

    TODOs:
        * The name ``value`` is used both for input and output, add another
            variable like ``extracted_value``, or change input ``value``
            to something like ``source``.

    """

    if bit_end < bit_start:
        raise UnexpectedException()
    
    value = value >> bit_start
    value &= (2 ** (bit_end - bit_start + 1)) - 1
    # TODO: unfold this logic.
    
    return value


def get_signed_value(value, bit_len):
    """Extract value as signed immediate.

    Interpret this Python int as a signed immediate of a specified
    bit len, to determine if it is a negative value.

    Args:
        value (int): Input value.
        bit_len (int): Length, in bits, of the input value.

    Returns:
        int: signed immediate.

    TODOs:
        * Same as before, don't abuse the term ``value``.

        * Decide between ``get_`` or ``extract_`` prefix for this kind of functions.

        * Clearly differenetiate between Python int and Hexagon immediate.

    """

    # Check MSB for the sign of the integer

    sign_bit = bit_len - 1
    if extract_bits(value, sign_bit, sign_bit) == 0:
        # MSB is zero, the value as such can be correctly interpreted.

        return value

    # If MSB is set, interpret as negative value (2's complement).

    all_ones_mask = (2 ** bit_len) - 1
    neg_value = (value ^ all_ones_mask) + 1

    return (-1) * neg_value


def standarize_syntax_objdump(syntax):
    """Change instruction syntax to match Qualcomm's objdump output.

    Args:
        syntax (str): instruction syntax, probably as was obtained from the parsed manual.

    Returns:
        str: matching objdump syntax (as close as possible).

    TODO:
        * Care should be taken not to modify the syntax patterns used in the decoder
            to recognize different attributes of the instruction, e.g., ``Rd`` can
            be splitted with a space like ``R d``.

        * Document the most complex regex.

    """

    # Add spaces to certain chars like '=' and '()'

    both_spaces = ['=','+','-','*','/', '&', '|', '<<', '^']
    left_space = ['(', '!']
    rigth_space = [')', ',']
    for c in both_spaces:
        syntax = syntax.replace(c, ' ' + c + ' ')
    for c in left_space:
        syntax = syntax.replace(c, ' ' + c)
    for c in rigth_space:
        syntax = syntax.replace(c, c + ' ')
     
    syntax = re.sub(r'\s{2,}', ' ', syntax)
     
    # TODO: Special hack for the unary minus.
    syntax = re.sub(r'\#\s-\s', '#-', syntax)
    
    syntax = re.sub(r'\(\s*', '(', syntax)
    syntax = re.sub(r'\s*\)', ')', syntax)
    
    # Compound assingment
    syntax = re.sub(r'([\+\-\*\/\&\|\^\!]) =', r'\1=', syntax)
    
    syntax = syntax.replace(' ,', ',')
    syntax = syntax.replace(' .', '.')
    
    # Remove parenthesis from (!p0.new). just to match objdump,
    # but I prefer it with parenthesis.
    if ';' not in syntax:
        m = re.search(r'\( (\s* ! \s* [pP]\w(.new)? \s*) \)', syntax, re.X)

        if m:
            syntax = syntax.replace('(' + m.group(1) + ')', m.group(1))
            # syntax = re.sub(r'\( (\s* ! \s* [pP]\w(.new)? \s*) \)', r'\1', syntax, re.X)
            # TODO: The re.sub is not working, don't know why..
        
    
    syntax = syntax.replace('dfcmp', 'cmp')
    syntax = syntax.replace('sfcmp', 'cmp')

    # Special cases: ++, ==, !=
    syntax = syntax.replace('+ +', '++')
    syntax = syntax.replace('= =', '==')
    syntax = syntax.replace('! =', '!=')
    
    syntax = syntax.strip()
    
    return syntax


def pv(name):
    """Print variable name and contents.

    Used only as a debugging tool, as it is very slow.
    Taken from: http://stackoverflow.com/a/2813384

    Attributes:
        name (str): variable name.

    """
    record = inspect.getouterframes(inspect.currentframe())[1]
    frame = record[0]
    val = eval(name, frame.f_globals, frame.f_locals)
    print('{0}: {1}'.format(name, val))


class HexagonPacket(object):
    """Hexagon packet.

    Attributes:
        instructions (List[HexagonInstruction]): contains all the instructions (found so far)
            belonging to this packet, sorted by ascending addresses, so the current
            instruction being disassembled is the end of the list.
        address (int): of the start of the packet.

    """
    __slots__ = ['instructions', 'address']

    def __init__(self, hi):

        self.instructions = [hi]
        self.address = hi.addr
    
    def n_inst(self):
        """Get the number of instructions in the package.

        Returns:
            int: number of instrucions.

        TODOs:
            * change name: get_inst_n ?.

        """
        return len(self.instructions)
    
    def get_last_inst(self):
        """Get the last (higher address) instruction in the packet.

        Returns:
            HexagonInstruction: last instruction.

        """
        return self.get_inst(-1)
    
    def get_before_last_inst(self):
        """Get next to last last instruction in the packet.

        Returns:
            HexagonInstruction: next to last instruction.

        TODOs:
            * change name: get_next_to_last_inst

        """
        return self.get_inst(-2)
    
    def add_next_inst(self, inst):
        """Add instruction to the end of the packet.

        Args:
            inst (HexagonInstruction): instruction to be added.

        Returns:
            None

        TODOs:
            * Check for packets of more than 4 instructions?

        """
        # if len(self.instructions) >= 4:
        #     raise UnknownInstructionException()
        # TODO: can't throw it here because disasm_one_inst won't catch it, its try-catch should be expanded.

        self.instructions.append(inst)

    def get_inst(self, n):
        """Get an instruction from the packet.

        Args:
            n (int): instruction index in the packet (list of instructions).

        Returns:
            HexagonInstruction: instruction indicated by the passed index from the list.

        TODOs:
            * Change name: get_inst_by_index ?
            * Change to an internal function (with _ or __ prefix?)

        """
        return self.instructions[n]

class HexagonInstruction(object):
    """Hexagon instruction.

    Attributes:
        syntax (str): Hexagon instruction syntax, as seen in the manual, e.g. ``Rd=add(Rs,#s16)``.
        fields (Dict[str, EncodingField]): instruction encoding fields, indexed by the field char,
            e.g. fields['d'] -> EncodingField(Rd).
        template (InstructionTemplate): from which the instruction was created.
        text (str): representation of a disassembled instruction.
        immext (Optional[int]): if not None, the instruction is a constant extender (whose
            syntax is ``immext``), and this attribute stores the extension value, which will
             be applied to the next instruction being disassembled.
        start_packet (bool): True if this instruction is the first one in the packet, False otherwise.
        end_packet (bool): True if this instruction is the last one in the packet, False otherwise.
        imm_ops (List[InstructionImmediate]): List of the instruction register operands.
        reg_ops (List[InstructionRegister]): List of the instruction immediate operands.
        parse_bits (int): Value extracted from the "Parse bits", bits 15:14 (inclusive),
            usually manipulated in binary form, e.g., compared 0b00 or 0b11 values,
            which indicates properties of the instruction, and how to interpret it.
        endloop (List[int]): if it contains '0', indicates that this instruction is
            the end of (hardware) ``loop0``; if it contains a '1', the end of ``loop1``.
        addr (int): Address of the instruction, used to determine if two instructions
            are in the same packet, it doesn't affect how it's disassembled.
        packet (HexagonPacket): that contains this instruction.
        is_duplex (bool): Indicates is this is a duplex instruction.
        is_unknown (bool): True if the disassembly process fails, indicating
            that this instruction is not included in the database and therefore
            the instruction is unknown to the disassembler; False otherwise.

    TODOs:
        * Document the class, not just its attributes.

        * Remove attributes `syntax`, fields`, is_duplex`, use the ones
            from the InstructionTemplate.

        * Prefix `start_packet`/`end_packet` with ``is_``.

        * Change `endloop` from List[int] to Set[int].

        * Add the instruction value (int) disassembled from which this object
            was created.

    """
    __slots__ = ['syntax', 'fields', 'template', 'text', 'immext',
                 'start_packet', 'end_packet',  'imm_ops', 'reg_ops',
                 'parse_bits', 'endloop', 'addr', 'packet', 'is_duplex',
                 'is_unknown']

    def __init__(self):

        self.syntax = None
        self.fields = {}
        self.template = None
        self.text = ''
        self.parse_bits = None
        self.endloop = []
        self.immext = None
        self.start_packet = None
        self.end_packet = None
        self.imm_ops = []
        self.reg_ops = []
        self.is_unknown = False

    def get_real_operand(self, template_op):
        """Get an instruction operand from the corresponding operand template of the instruction.

        As not to repeat data, information regarding the instruction defintion, and not the
        actual instruction is stored in the InstructionTemplate (and RegisterTemplate,
        ImmediateTemplate, etc.); it's not stored again inside HexagonInstruction. Therefore,
        many times, to get all the information from, e.g., a register, both the InstructionRegister
        and the RegisterTemplate need to be available, this function is a convenient way to
        get the second from the first.

        Args:
            template_op (OperandTemplate): Either RegisterTemplate or ImmediateTemplate that
                is linked to an InstructionRegister or InstructionImmediate.

        Returns:
            InstructionOperand: Created from the OperandTemplate attribute during the
                disassembly of the instruction.

        TODOs:
            * All the operands are being searched with a for loop, a dedicated dict
                could be used for this task (although the profiling doesn't show
                this function as much time consuming).

            * Is it ok to do id comparisons of the sort ``op.template is template_op``? It should
                be ok, the template operand object is the same for all the instructions  that
                share the same template.

        """
        if isinstance(template_op, RegisterTemplate):
            for op in self.reg_ops:
                if op.template is template_op:

                    return op
        elif isinstance(template_op, ImmediateTemplate):
            for op in self.imm_ops:
                if op.template is template_op:
                    return op
        
        raise UnexpectedException()
        # The InstructionOperand should always be found.


class OperandTemplate(object):
    # TODO: Document class.

    __slots__ = ['syntax_name']
    # TODO: Change `syntax_name` to ``syntax``.

    def __init__(self, syntax_name):
        self.syntax_name = syntax_name


class RegisterTemplate(OperandTemplate):
    # TODO: Document class.

    __slots__ = ['is_register_pair']

    def __init__(self, syntax_name):
        super().__init__(syntax_name)
        self.is_register_pair = False
        
        # Register pair analysis.

        if self.syntax_name[0] == 'R':
            # General register.

            if len(self.syntax_name[1:]) == 2:
                self.is_register_pair = True
                
                if self.syntax_name[1] != self.syntax_name[2]:
                    # the two chars of the register pair do not match
                    raise UnexpectedException("The two chars of the register pair do not match:"
                                              "'{:s}' and '{:s}'".format(self.syntax_name[1], self.syntax_name[2]))

        # TODO: I don't know if this is the best place to do this type of analysis
        # (and there is also an overlapping with the register templates).

        # TODO: Check if the general purpose register is the only that uses reg. pairs.
        # (the control reg is also possible as reg. pair but they are usually rreferencedby their alias)

        return


class ImmediateTemplate(OperandTemplate):
    # TODO: Document class. Develop the notion of immediate type, e.g., r, m, s, etc.

    __slots__ = ['scaled', 'type']
    # TODO: Change `scaled` to ``scale`` (because it's used as an int, not a bool).

    def __init__(self, syntax_name, scaled = 0):
        super().__init__(syntax_name)
        self.scaled = scaled

        self.type = self.syntax_name[1].lower()

        if self.type not in ['s', 'u', 'm', 'r']:
            raise UnexpectedException("Unknown immediate type: {:s}".format(self.type))


class InstructionOperand(object):
    # TODO: Document class.

    __slots__ = ['field_value', 'template', 'print_format', 'field_char']
    # TODO: Change `print_format` to ``text_format`` or ``text_output_format``.

    def __init__(self):
        pass


class InstructionRegister(InstructionOperand):
    # TODO: Document class.

    __slots__ = ['name']
    # TODO: There's some clash with `syntax_name` of template operands,
    # which should be named just ``syntax``.

    def __init__(self):
        self.name = None

    def __repr__(self):
        return self.name


class InstructionImmediate(InstructionOperand):
    # TODO: Document class.

    __slots__ = ['is_extended', 'value']

    def __init__(self):
        self.is_extended = False
        self.value = None

    def __repr__(self):
        return self.print_format.format(self.value)


def pickle_dump(filename, data):
    inst_pkl_file = open(filename, 'wb')
    # TODO: Use  Python `with` statement.

    pickle.dump(data, inst_pkl_file, protocol = -1)
    # The protocol is -1 used to avoid: "TypeError: a class that defines __slots__
    # without defining __getstate__ cannot be pickled".
    # Fixed suggested by: http://stackoverflow.com/a/2204702


def pickle_load(filename):
    inst_pkl_file = open(filename, 'rb')
    # TODO: Use  Python `with` statement.

    return pickle.load(inst_pkl_file)


def enclose(s):
    return "(" + s + ")"
    # TODO: Is this even used anymore?
