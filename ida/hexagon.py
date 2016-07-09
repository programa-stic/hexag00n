import idaapi
from idaapi import *

import re
import cProfile
import os

import hexagondisasm
from hexagondisasm.disassembler import HexagonDisassembler
from hexagondisasm.common import TemplateBranch, InstructionRegister, InstructionImmediate
from hexagondisasm.common import INST_SIZE, PACKET_MAX_SIZE


class hexagon_processor_t(idaapi.processor_t):
    """
    Processor module classes must derive from idaapi.processor_t

    The required and optional attributes/callbacks are illustrated in this template
    """

    # IDP id ( Numbers above 0x8000 are reserved for the third-party modules)
    id = 0x8000 + 1

    # Processor features
    flag = PR_ASSEMBLE | PR_SEGS | PR_DEFSEG32 | PR_USE32 | PRN_HEX | PR_RNAMESOK | PR_NO_SEGMOVE | PR_DELAYED #TODO: CHeck flags

    # Number of bits in a byte for code segments (usually 8)
    # IDA supports values up to 32 bits
    cnbits = 8

    # Number of bits in a byte for non-code segments (usually 8)
    # IDA supports values up to 32 bits
    dnbits = 8

    # short processor names
    # Each name should be shorter than 9 characters
    psnames = ['QDSP6V5']

    # long processor names
    # No restriction on name lengthes.
    plnames = ['Qualcomm Hexagon DSP v5']

    # register names
    regNames = [
        # General purpose registers
        "SP", # aka R0
        "R1",
        "R2",
        "R3",
        "R4",
        "R5",
        "R6",
        "R7",
        # VM registers
        "FLAGS", # 0
        "IP",    # 1
        "VM2",
        "VM3",
        "VM4",
        "VM5",
        "VM6",
        "VM7",
        # Fake segment registers
        "CS",
        "DS"
    ]

    # number of registers (optional: deduced from the len(regNames))
    regsNum = len(regNames)

    # Segment register information (use virtual CS and DS registers if your
    # processor doesn't have segment registers):
    regFirstSreg = 16 # index of CS
    regLastSreg  = 17 # index of DS

    # size of a segment register in bytes
    segreg_size = 0

    # You should define 2 virtual segment registers for CS and DS.

    # number of CS/DS registers
    regCodeSreg = 16
    regDataSreg = 17

    # Array of typical code start sequences (optional)
    # codestart = ['\x55\x8B', '\x50\x51']

    # Array of 'return' instruction opcodes (optional)
    # retcodes = ['\xC3', '\xC2']

    # Array of instructions
    # TODO: this is just to emulate the names from the hexagon.cpp proc module
    # mixed with the logic of the python proc modules, but has to be rewritten, it doesn't make sense
    instruc_id = {
        'other': {'name': '',  'feature': 0},
        'call': {'name': 'call', 'feature': CF_CALL},
        'jump': {'name': 'jump', 'feature': CF_JUMP | CF_STOP},
        'cond_jump': {'name': 'jump', 'feature': CF_JUMP},
    }
    
    # TODO: init regs like msp430
    insn_other = 0
    insn_call = 1
    insn_jump = 2
    insn_stop = 3

    # icode of the first instruction
    instruc_start = 0

    # Size of long double (tbyte) for this processor (meaningful only if ash.a_tbyte != NULL) (optional)
    tbyte_size = 0

    #
    # Number of digits in floating numbers after the decimal point.
    # If an element of this array equals 0, then the corresponding
    # floating point data is not used for the processor.
    # This array is used to align numbers in the output.
    #      real_width[0] - number of digits for short floats (only PDP-11 has them)
    #      real_width[1] - number of digits for "float"
    #      real_width[2] - number of digits for "double"
    #      real_width[3] - number of digits for "long double"
    # Example: IBM PC module has { 0,7,15,19 }
    #
    # (optional)
    real_width = (0, 7, 15, 0)

    # icode (or instruction number) of return instruction. It is ok to give any of possible return
    # instructions
    icode_return = 5

    # If the FIXUP_VHIGH and FIXUP_VLOW fixup types are supported
    # then the number of bits in the HIGH part. For example,
    # SPARC will have here 22 because it has HIGH22 and LOW10 relocations.
    # See also: the description of PR_FULL_HIFXP bit
    # (optional)
    high_fixup_bits = 0

    # only one assembler is supported
    assembler = {
        # flag
        'flag' : ASH_HEXF3|ASD_DECF0|ASO_OCTF1|ASB_BINF3|AS_N2CHR|AS_LALIGN|AS_1TEXT|AS_ONEDUP|AS_COLON, #TODO: CHeck flags

        # user defined flags (local only for IDP) (optional)
        'uflag' : 0,

        # Assembler name (displayed in menus)
        'name': "My processor module bytecode assembler",

        # array of automatically generated header lines they appear at the start of disassembled text (optional)
        'header': ["Line1", "Line2"],

        # array of unsupported instructions (array of cmd.itype) (optional)
        # 'badworks': [6, 11],

        # org directive
        'origin': "org",

        # end directive
        'end': "end",

        # comment string (see also cmnt2)
        'cmnt': ";",

        # ASCII string delimiter
        'ascsep': "\"",

        # ASCII char constant delimiter
        'accsep': "'",

        # ASCII special chars (they can't appear in character and ascii constants)
        'esccodes': "\"'",

        #
        #      Data representation (db,dw,...):
        #
        # ASCII string directive
        'a_ascii': "db",

        # byte directive
        'a_byte': "db",

        # word directive
        'a_word': "dw",

        # remove if not allowed
        'a_dword': "dd",

        # remove if not allowed
        'a_qword': "dq",

        # remove if not allowed
        'a_oword': "xmmword",

        # remove if not allowed
        'a_yword': "ymmword",

        # float;  4bytes; remove if not allowed
        'a_float': "dd",

        # double; 8bytes; NULL if not allowed
        'a_double': "dq",

        # long double;    NULL if not allowed
        'a_tbyte': "dt",

        # packed decimal real; remove if not allowed (optional)
        'a_packreal': "",

        # array keyword. the following
        # sequences may appear:
        #      #h - header
        #      #d - size
        #      #v - value
        #      #s(b,w,l,q,f,d,o) - size specifiers
        #                        for byte,word,
        #                            dword,qword,
        #                            float,double,oword
        'a_dups': "#d dup(#v)",

        # uninitialized data directive (should include '%s' for the size of data)
        'a_bss': "%s dup ?",

        # 'equ' Used if AS_UNEQU is set (optional)
        'a_equ': ".equ",

        # 'seg ' prefix (example: push seg seg001)
        'a_seg': "seg",

        # current IP (instruction pointer) symbol in assembler
        'a_curip': "$",

        # "public" name keyword. NULL-gen default, ""-do not generate
        'a_public': "public",

        # "weak"   name keyword. NULL-gen default, ""-do not generate
        'a_weak': "weak",

        # "extrn"  name keyword
        'a_extrn': "extrn",

        # "comm" (communal variable)
        'a_comdef': "",

        # "align" keyword
        'a_align': "align",

        # Left and right braces used in complex expressions
        'lbrace': "(",
        'rbrace': ")",

        # %  mod     assembler time operation
        'a_mod': "%",

        # &  bit and assembler time operation
        'a_band': "&",

        # |  bit or  assembler time operation
        'a_bor': "|",

        # ^  bit xor assembler time operation
        'a_xor': "^",

        # ~  bit not assembler time operation
        'a_bnot': "~",

        # << shift left assembler time operation
        'a_shl': "<<",

        # >> shift right assembler time operation
        'a_shr': ">>",

        # size of type (format string) (optional)
        'a_sizeof_fmt': "size %s",

        'flag2': 0,

        # comment close string (optional)
        # this is used to denote a string which closes comments, for example, if the comments are represented with (* ... *)
        # then cmnt = "(*" and cmnt2 = "*)"
        'cmnt2': "",

        # low8 operation, should contain %s for the operand (optional fields)
        'low8': "",
        'high8': "",
        'low16': "",
        'high16': "",

        # the include directive (format string) (optional)
        'a_include_fmt': "include %s",

        # if a named item is a structure and displayed  in the verbose (multiline) form then display the name
        # as printf(a_strucname_fmt, typename)
        # (for asms with type checking, e.g. tasm ideal)
        # (optional)
        'a_vstruc_fmt': "",

        # 3-byte data (optional)
        'a_3byte': "",

        # 'rva' keyword for image based offsets (optional)
        # (see nalt.hpp, REFINFO_RVA)
        'a_rva': "rva"
    } # Assembler


    # Removed almost all optional callbacks from template (most of them notifications).
    # TODO: Check again later to see if any of the notifications are useful.
    
    def notify_is_basic_block_end(self, call_insn_stops_block):
        """
        Is the current instruction end of a basic block?
        This function should be defined for processors
        with delayed jump slots. The current instruction
        is stored in 'cmd'
        args:
          call_insn_stops_block
          returns: 1-unknown, 0-no, 2-yes
        """

        if self.cmd.hi.end_packet and self.cmd.hp.packet_has_any_jump_inst:
            return 2
        else:
            return 0

    
    # ----------------------------------------------------------------------
    # ----------------------------------------------------------------------
    #             The following callbacks are mandatory
    # ----------------------------------------------------------------------
    # ----------------------------------------------------------------------

    def emu(self):
        """
        Emulate instruction, create cross-references, plan to analyze
        subsequent instructions, modify flags etc. Upon entrance to this function
        all information about the instruction is in 'cmd' structure.
        If zero is returned, the kernel will delete the instruction.
        """
        
        self.profiler.enable()

        
        self.log_with_addr("emu")
                
        if not (self.cmd.hi.end_packet and self.cmd.hp.packet_has_uncond_jump_inst):
            ua_add_cref(0, self.cmd.ea + self.cmd.size, fl_F)
            self.log_with_addr("ua_add_cref(0, {:s}, fl_F)".format(hex(self.cmd.ea + self.cmd.size)))
        
        for i in range(self.op_i + 1):
            op = self.cmd.Operands[i]
            
            #TODO: Check that all operands are initialized to o_void in each cycle by the IDA kernel (i think i read that somewhere in the sdk doc)
            
            if op.type == o_near:
                if self.cmd.itype == self.itype_call:
                    if not self.relocatable_file:
                        ua_add_cref(0, op.addr, fl_CN)
                        # Relocatable files in Hexagon haven't been processed by the IDA ELF loader
                        self.log_with_addr("ua_add_cref(0, op.addr = {:s}, fl_CN)".format(hex(op.addr)))
                elif self.cmd.itype == self.itype_jump or self.cmd.itype == self.itype_cond_jump:
                    ua_add_cref(0, op.addr, fl_JN)
                    self.log_with_addr("ua_add_cref(0, op.addr = {:s}, fl_JN)".format(hex(op.addr)))

        # Perform data cross references
        # -----------------------------
        #
        # As the instruction behavior (from the manual) is not yet analyzed, and the REIL translation
        # is also not available for now, any immediate operand is interpreted as a potential data address,
        # and a data reference is performed, with the exceptions:
        #
        # 1. The immediate value is the target of a branch (that turns it into a code reference,
        #       handled earlier in the function).
        # 2. The immediate value does not represent a valid address within the binary.
        #
        # For now this feature has to be explicitly enabled with ``IDP_ENABLE_DATA_REFS`` (environ.
        # variable) because it is causing IDA to disassemble unaligned instruction addresses (a behavior
        # that is warned with the message ``Unaligned instruction address``).

        if os.getenv("IDP_ENABLE_DATA_REFS"):

            for imm_op in self.cmd.hi.imm_ops:
                # Iterate all imm. ops.

                # Skip exception 1.

                if self.cmd.hi.template and self.cmd.hi.template.branch:
                    branch = self.cmd.hi.template.branch
                    # There is a branch in the instruction.

                    if branch.type in [TemplateBranch.jump_imm_syntax, TemplateBranch.call_imm_syntax]:
                        if self.cmd.hi.get_real_operand(branch.target).value == imm_op.value:
                            continue
                            # The branch has an imm. op as the target, and its value is the current
                            # imm. analyzed in this iteration.

                # Skip exception 2.
                if not isEnabled(imm_op.value):
                    continue

                # Perform the data reference.

                ua_add_dref(0, imm_op.value, dr_R)
                self.log_with_addr("ua_add_dref(0, {:s}, dr_R)".format(hex(imm_op.value)))
                # TODO: Figure out which data reference to use (this one or `ua_add_off_drefs` like
                # in gsmk's proc. module), the safest choice seems to be read data (`dr_R`) reference,
                # because an offset reference can be associated with instructions.

        self.profiler.disable()

        return 1

    def outop(self, op):
        """
        Generate text representation of an instructon operand.
        This function shouldn't change the database, flags or anything else.
        All these actions should be performed only by u_emu() function.
        The output text is placed in the output buffer initialized with init_output_buffer()
        This function uses out_...() functions from ua.hpp to generate the operand text
        Returns: 1-ok, 0-operand is hidden.
        """
        return True

    def out_operands_separately(self, hi):
        # TODO: figure out the relationship between out/outop/out_one_operand...
        # TODO: Set up peppery each operand in the ana() stage, I'm abusing the Op[0] (but IDA isn't complaining)

        if hi.start_packet:
            out_keyword('{ ')
        else:
            out_keyword('  ')
        # TODO: this logic is a copy from the disasm text handling, tokens and text should be unified

        for token in hi.template.tokens:
            if token.op is None:
                out_keyword(str(token.s))
                continue
            
            inst_op = hi.get_real_operand(token.op)
             
            # Branch operand case: out the label expression if possible
            if hi.template.branch:
                branch = hi.template.branch
                 
                if branch.type in [TemplateBranch.jump_imm_syntax, TemplateBranch.call_imm_syntax] and branch.target == token.op:
                    self.cmd.Operands[0].type = o_near
                    self.cmd.Operands[0].addr = inst_op.value
                    self.cmd.Operands[0].dtyp = dt_code
                    # TODO: I'm abusing the Operands array, but IDA doesn't seem to mind.
    
                    name_expr = get_name_expr(self.cmd.ea, 0, self.cmd.Operands[0].addr, self.cmd.Operands[0].addr)
                    # TODO: can't find the IDA Python doc for this, I'm assuming it returns a string
                     
                    if name_expr and name_expr != "":
                        OutLine(name_expr)
                    else:
                        OutValue(self.cmd.Operands[0], OOF_ADDR)
                    
                    continue
                         
                    
            # Generic case: out as imm or reg
            if isinstance(inst_op, InstructionImmediate):
                self.cmd.Operands[0].type = o_imm
                self.cmd.Operands[0].value = inst_op.value
                self.cmd.Operands[0].dtyp = dt_dword
                OutValue(self.cmd.Operands[0], OOFW_IMM)
                
            elif isinstance(inst_op, InstructionRegister):
                out_register(str(repr(inst_op)))
                
            else:
                raise
        
        if hi.end_packet:
            out_keyword(' }')

                
    def out(self):
        """
        Generate text representation of an instruction in 'cmd' structure.
        This function shouldn't change the database, flags or anything else.
        All these actions should be performed only by u_emu() function.
        Returns: nothing
        """
        
        self.profiler.enable()

#         self.log_custom("out({:s})".format(hex(self.cmd.ea)))

        buf = idaapi.init_output_buffer(1024)

        hi = self.disasm_one_inst(idaapi.get_long(self.cmd.ea), self.cmd.ea)
        # TODO: can I assume the cmd object is already set with the ana() information? as not to call the disasm again
        # and disrupt the packet disasm flow order

        if hi.template is None or hi.is_unknown or os.getenv("IDP_OUT_SIMPLE_SYNTAX"):
            out_keyword(str(hi.text))
            # This simple syntax is useful to produce generic asm code for comparison
        else:
            self.out_operands_separately(hi)

        # The str() conversion is necessary because the HexagonDisassembler uses the
        # python future compatibility module that uses unicode as default strings,
        # and IDA can't handle that.
        # TODO: maybe I shoud convert everythin to str() in the disasm (or don't use the future.unicode import)
        
        # TODO: Split in out() and out_one_operand()
        
        term_output_buffer()
        cvar.gl_comm = 1 # show IDA comments (http://www.hexblog.com/?p=116)
        MakeLine(buf)
        
        self.profiler.disable()
        
        return
    
    def ana(self):
        """
        Decodes an instruction into self.cmd.
        Returns: self.cmd.size (=the size of the decoded instruction) or zero
        """
        
        self.profiler.enable()
        
        self.init_operands()
        
        inst = ua_next_long()
        
        self.log_with_addr("ana")
        
        # TODO: How to handle and really identify "<unknown>".
#         if "<unknown>" in self.disasm_addr(self.cmd.ea):
#             return 0

        self.cmd.hi = self.disasm_one_inst(inst, self.cmd.ea)
        inst_str = str(self.cmd.hi.text)
        
        self.cmd.itype = self.itype_other
        
        if "<unknown>" in inst_str:
            return self.cmd.size
        
        # I'm analyzing the next instrcution, if it's in the same packet
        # it will share the same packet information class
        if '{' in inst_str or self.cmd.ea != self.prev_addr_analyzed + 4:
            self.cmd.hp = hexagon_packet()
            self.current_hex_packet = self.cmd.hp
        else:
            self.cmd.hp = self.current_hex_packet
        
        self.do_analysis()
        
        self.prev_addr_analyzed = self.cmd.ea
        
        self.profiler.disable()
        
        # Return decoded instruction size or zero
        return self.cmd.size


    def do_analysis(self):
        if self.cmd.hi.template and self.cmd.hi.template.branch:
            branch = self.cmd.hi.template.branch

            if branch.type in [TemplateBranch.jump_imm_syntax, TemplateBranch.jump_reg_syntax, TemplateBranch.dealloc_ret_syntax]:
                self.cmd.hp.packet_has_any_jump_inst = True
                if branch.is_conditional:
                    self.cmd.itype = self.itype_cond_jump
                else:
                    self.cmd.itype = self.itype_jump
                    self.cmd.hp.packet_has_uncond_jump_inst = True
            else:
                self.cmd.itype = self.itype_call

            if branch.type in [TemplateBranch.jump_imm_syntax, TemplateBranch.call_imm_syntax]:
                op = self.get_next_operand()
                op.type = o_near
                op.d_type = dt_dword
                op.addr = self.cmd.hi.get_real_operand(branch.target).value

#                 self.log_with_addr("Target imm: {:x}".format(op.addr))
                
        return
    
    
    # ----------------------------------------------------------------------
    # ----------------------------------------------------------------------
    #                      Parsing functions.
    # ----------------------------------------------------------------------
    # ----------------------------------------------------------------------

    
    # There's an intrinsic problem with IDA's limitation of 6 operands and the fact
    # that Hexagon has many subinstructions in the 32 bit full instruction. I don't
    # know how important is to load the information about the operands, is it just for me
    # or the IDA kernel uses this values? Besides for printing them, which I dont
    # care about since the output stage is taken care of with the objdump.
    def get_next_operand(self):
        self.op_i += 1
        
        if self.op_i > 6: # This is trouble, I don't know how to handle this yet
            raise
        
        return self.cmd.Operands[self.op_i]
    
    def init_operands(self):
        self.op = None
        self.op_i = -1
        self.cmd.Op1.type = o_void # just to signal that there are no operands set so far
    
    # ----------------------------------------------------------------------
    # ----------------------------------------------------------------------
    #                      General functions.
    # ----------------------------------------------------------------------
    # ----------------------------------------------------------------------

    def log_with_addr(self, log_str):
        self.log_custom("EA: {:08x}: ".format(self.cmd.ea) + log_str)

    def log_custom(self, log_str):
        if os.getenv("IDP_LOGGING"):
            Message(log_str + "\n") # Goes to Output Window

#         self.logger.write(log_str + '\n')
#         self.logger.flush()

        # TODO: logging module is not working for real time debugging.
#         logging.debug(log_str)
        pass
    
    def disasm_one_inst(self, inst, addr):
        
        if addr % 4 != 0:
            if not os.getenv("IDP_UNALIGNED_WARNING"):
                Warning("Unaligned instruction address: {:x} ".format(addr))
                os.environ["IDP_UNALIGNED_WARNING"] = "Warned."

            self.log_with_addr("Unaligned instruction address.")
                    
        if len(self.disasm_cache) > 0x10000:
            # TODO: Ideally disasm_cache would be an OrderedDict, but there's no C implementation in Pyhton 2, and this really slows it down.
            self.disasm_cache = {}
        
        # I'm assuming the jumps are always to packet start addresses, so I also disassemble
        # the rest of the packet instructions
        # TODO: can i assume that? i still have to disassemble till the end of the packet, always.

        for packet_addr in range(addr, addr + PACKET_MAX_SIZE, INST_SIZE):

            if idaapi.isLoaded(packet_addr):
                hi = self.disasm_wrapper(idaapi.get_long(packet_addr), packet_addr)
                if addr == packet_addr:
                    self.log_with_addr("Disassembling packet {:08x}: {:s}".format(packet_addr, str(hi.text)))
                if hi.end_packet:
                    break
            else:
                break
                
        return self.disasm_wrapper(inst, addr)
                
    def disasm_wrapper(self, inst, addr):
        if addr not in self.disasm_cache:
            self.disasm_cache[addr] = self.hd.disasm_one_inst(inst, addr)
        
        return self.disasm_cache[addr]

    def init_instructions(self):
        self.instruc = []
        i = 0
        for inst_id, inst in self.instruc_id.items():
            setattr(self, 'itype_' + inst_id, i)
            self.instruc.append(inst)
            i += 1

        # icode of the last instruction + 1
        self.instruc_end = len(self.instruc)

    def __init__(self):
        idaapi.processor_t.__init__(self)

        # TODO: logging not working.
        # self.work_folder = ""
        # self.log_fn = self.work_folder + 'work.log'
        # logging.basicConfig(filename=self.log_fn, level=logging.DEBUG, filemode='w')
        # self.logger = open(self.log_fn, 'w')
        
        self.relocatable_file = re.search(r'\.o$', GetInputFile()) != None
        
        self.init_instructions()
        self.prev_addr_analyzed = -1
        self.current_hex_packet = None
        self.hd = HexagonDisassembler()
        # TODO: this should be instatiated on demand, because I think the init is called every time IDA starts
        self.disasm_cache = {}
        # TODO: use orderdict to remove old entries

        self.profiler = cProfile.Profile()
        hexagondisasm.profiler = self.profiler
        # TODO: I don't know how to access this class from the IDA Python
        # console to get the profiler, I do it through the module


def enclose(s):
    return "(" + s + ")"

"""
I'm attaching this class to the cmd structure, to customize it for the
hexagon instruction properties. I'm setting the cmd with the minimum info,
I'm not sure how much of it is for the IDA kernel to analyze and how much
is just a utility class to pass information between ana() and emu(). 
"""
class hexagon_packet():
    # TODO: unify this with hexagondisasm.common.HexagonPacket
    
    def __init__(self,):
        self.packet_has_any_jump_inst = False
        self.packet_has_uncond_jump_inst = False
    
# ----------------------------------------------------------------------
# Every processor module script must provide this function.
# It should return a new instance of a class derived from idaapi.processor_t
def PROCESSOR_ENTRY():
    return hexagon_processor_t()
