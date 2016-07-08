from __future__ import (absolute_import, division,
                        print_function, unicode_literals)

from builtins import (ascii, bytes, chr, dict, filter, hex, input,
                      int, map, next, oct, open, pow, range, round,
                      str, super, zip)

from hexagondisasm import common
from hexagondisasm.common import InstructionTemplate, TemplateToken, TemplateBranch
from hexagondisasm.common import UnexpectedException

import re

class HexagonInstructionDecoder(object):
    """Hexagon instruction decoder.

    Takes instruction definitions and process them to instruction templates.

    Attributes:
        inst_def_list (List[InstructionDefintion]): List of instruction definitions saved during the parsing stage.
        inst_template_list (List[InstructionTemplate]): List of instruction definitions templates generated
            by the decoder from the list of definitions.

    """
    __slots__ = ['inst_def_list', 'inst_template_list']

    def __init__(self):
        """Load the instruction definitions and convert it to instruction templates.

        Creates the InstructionTemplate and processes it.

        TODOs:
            * All the calls in the loop could be done inside the InstructionTemplate
                constructor, should it?

        """
        self.inst_def_list = common.pickle_load(common.INST_DEF_PATH)
        self.inst_template_list = [InstructionTemplate(inst_def) for inst_def in self.inst_def_list]

        for template in self.inst_template_list:
            self.analyze_branch(template)
            self.resolve_constant_extender(template)
            self.tokenize_syntax(template)

    def tokenize_syntax(self, template):
        """Generate a list of tokens from the instruction syntax.

        Takes the syntax string and split it in smaller strings (tokens). The split is
        done to generate a link between the instruction operands and the substrings
        that correspond to it, e.g., ``Rd=add(Rs,#s16)`` would be splitted like:
        ``['Rd', '=add(', 'Rs', ',', '#s16', ')']`` to isolate the three operand strings
        (registers ``Rd``, ``Rs`` and immediate ``#s16``) from the rest of the
        syntax string.

        The substrings are later used to generate TemplateToken objects, which are composed
        of a string with its associated operand (if it exists).

        Args:
            template (InstructionTemplate): to be processed.

        Returns:
            None: the data is applied to the template itself.

        TODOs:
            * Should the 2 steps (split and match) be done together?

        """
        tokens = [template.syntax] # type: List[str]
        # The syntax will be splitted to this list of strings that will be later
        # used to create the template tokens.

        for op in template.reg_ops + template.imm_ops:  # type: InstructionOperand

            new_tokens = [] # type: List[str]
            # New tokens generated from the current tokens, updated at the end of the loop.
            
            for str_token in tokens:
                new_tokens.extend(
                    re.split('(' + op.syntax_name + ')', str_token)
                )
                # If a operand is found in the current token, split it to isolate
                # the operand, re.split is used because, unlike string.split, it doesn't
                # discard the separator (the operator name in this case) when enclosed
                # in parenthesis.
            
            if len(new_tokens) != len(tokens) + 2 * template.syntax.count(op.syntax_name):
                raise UnexpectedException()
                # Every split (appearance of the operand in the syntax)
                # has to generate 2 new tokens (an old token is split into 3,
                # the separator and left/right tokens, that are always generated
                # even if they are empty strings).
                
            tokens = new_tokens
            # TODO: use list comprehensions and eliminate `new_tokens`.
        
        # Discard possibly empty generated strings.
        tokens = list(filter(lambda s: len(s) > 0, tokens))

        # Generate list of TemplateToken and match string tokens to operands.

        for str_token in tokens:

            template_token = TemplateToken(str_token.lower())
            # TODO: Is it ok to convert to lowercase here?
            # The letter case of the operands text is useful (specially in IDA) to
            # identify them quickly in the visual analysis (from the rest of the instruction).

            for op in template.reg_ops + template.imm_ops: # type: InstructionOperand

                if str_token == op.syntax_name:
                    # The string token names the operand, match them.

                    template_token.op = op
                    break
                
            template.tokens.append(template_token)

        return
        
    def resolve_constant_extender(self, template):
        """In case there are two imm. operands, indicate to which one would apply a constant extension.

        This is done for instructions that can be extended by a constant but have two
        immediate operands and it has to be indicated to which one the extension applies.

        The function ``apply_extension()`` in instruction behaviours is used as an indication
        that a constant extension can be applied, and the argument of the function specifies
        the syntax of which immediate operand it applies to.

        Args:
            template (InstructionTemplate): to be processed.

        Returns:
            None: the data is applied to the template itself.

        TODOs:
            * Add to the function description an example of an instruction where
                there are two imm. ops. and the ``apply_extension()`` resolves which one.

        """
        if len(template.imm_ops) < 2:
            # There's no need to perform the check, there's (at most) only one
            # immediate operand to choose from.
            return

        m = re.search(r"""
            # Looking for something like: "apply_extension(...);"

            apply_extension
            \(
                (.*?)           # Capture group for the imm. op. name, e.g., ``#s``.
            \)
        """, template.behavior.replace(' ', ''), re.X)
        # The spaces are removed from the behavior string to simplify the regex.

        if m is None:
            # No constant extension found in the behavior.
            return

        imm_op_ext_name = m.group(1)
        # Name of the imm. op. that is the argument of ``apply_extension()``.

        for imm_op in template.imm_ops:
            if imm_op_ext_name in imm_op.syntax_name:
                # An equal comparison is not made in the previous if because
                # the op. name in the apply_extension argument is usually a shorter
                # version of the name in the syntax (normally because the
                # operand's bit size was removed), e.g., ``#s16`` in
                # ``Rd=add(Rs,#s16)`` is referenced as ``apply_extension(#s);``.

                template.imm_ext_op = imm_op
                return
        
        raise UnexpectedException()
        # If the regex matched, the operand should have been found in the previous loop.
        
    def analyze_branch(self, template):
        """Find a branch in the instruction syntax and generate the template info.

        Used in (IDA) static analysis.

        Args:
            template (InstructionTemplate): to be processed.

        Returns:
            None: the data is applied to the template itself.

        TODOs:
            * Change function name to something like 'find_branch(es)'.

            * This type of analysis should be done by studying the REIL translation
                of the instruction, which truly reflects its behaviour. When the REIL
                translation is added this function should be adapted.

            * Multiple branches in one instruction: is it possible? I think not,
                at most, two branches in one packet but separate. Check this.

            * The branch string itself is used to represent it, maybe some constants
                should be used instead.

        """
        for branch_syntax in TemplateBranch.all_branches: # type: str
            # Find any of the possible branch syntaxes in the instruction
            # to detect a branch.
            m = re.search(branch_syntax, template.syntax, re.X)
            if m is None:
                continue

            if branch_syntax == TemplateBranch.dealloc_ret_syntax:
                # The instruction is a 'dealloc_return', a jump to the
                # LR as target.
                return
                # TODO: Should this case be handled? Is it of interest to static analysis?

            template.branch = TemplateBranch(branch_syntax)

            template.branch.is_conditional = ('if' in template.syntax)
            # TODO: The if could be applying to another sub-instruction. Improve detection.
            
            if branch_syntax in [TemplateBranch.jump_reg_syntax, TemplateBranch.call_reg_syntax]:
                # Branch type: jump/call register.

                # Find which register is the target of the branch.

                for reg in template.reg_ops: # type: RegisterTemplate
                    m = re.search(branch_syntax + r'\s*' + reg.syntax_name, template.syntax, re.X)
                    if m:
                        template.branch.target = reg
                        return

                # The target register operand was not found, this shouldn't happen, but
                # for now the case of register alias (specially the case of LR) is not
                # being handled, so an exception can't be raised, and this case is
                # tolerated (retuning instead).

                # raise UnexpectedException()
                return

            if branch_syntax in [TemplateBranch.jump_imm_syntax, TemplateBranch.call_imm_syntax]:
                # Branch type: jump/call immediate.

                for imm in template.imm_ops: # type: ImmediateTemplate
                    m = re.search(branch_syntax + r'\s*' + imm.syntax_name.replace('#', r'\#'), template.syntax, re.X)
                    # The '#' (used in imm. op. names) is escaped, as it is interpreted as
                    # a comment in verbose regex (re.X), and verbose regex is used because
                    # the branch syntax is written with spaces (verbose style) to improve
                    # its readability.

                    if m:
                        template.branch.target = imm
                        return

                raise UnexpectedException()
                # The target immediate operand should have been found.

        return
    
if __name__ == "__main__":
    
    print("Starting decodification...")

    deco = HexagonInstructionDecoder()
    
    common.pickle_dump(common.INST_TEMPL_PATH, deco.inst_template_list)
    
    print("Decoding done.")

    # TODO: move this to a general main, to call the importer together with the decoder.
