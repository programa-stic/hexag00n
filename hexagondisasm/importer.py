from __future__ import (absolute_import, division,
                        print_function, unicode_literals)

from builtins import (ascii, bytes, chr, dict, filter, hex, input,
                      int, map, next, oct, open, pow, range, round,
                      str, super, zip)

import re
import sys
from hexagondisasm.common import UnexpectedException, InstructionDefinition
from hexagondisasm.common import pickle_dump, pv, INST_DEF_PATH


class ManualParser:
    
    def __init__(self, manual_fn):
        self.manual = open(manual_fn, 'rU') # U: universal newlines, to get rid of '\r' when opening in linux
        self.lines = self.manual.read().splitlines()
        self.ln = 0
        self.current_line = self.lines[self.ln]
        
        # TODO: change the name, this are not yet instruction templates until the decoder process them
        self.instructions = []
        
        self.syntax_behavior_text = []
        
        
        self.current_inst_name = None
        self.total_encodings = 0
        
    def get_next_line(self):
        self.ln += 1
        
        if self.ln == len(self.lines):
            raise self.OutOfLinesException()
        
        return self.get_current_line()
    
    def peek_next_line(self):
        if self.ln + 1 == len(self.lines):
            raise self.OutOfLinesException()
        
        return self.lines[self.ln + 1]
    
    def peek_prev_line(self):
        if self.ln - 1 == -1:
            raise self.OutOfLinesException()
        
        return self.lines[self.ln - 1]
    
    def get_current_line(self):
        self.current_line = self.lines[self.ln]
        return self.current_line
        
    def get_prev_line(self):
        self.ln -= 1
        
        if self.ln < 0:
            raise self.UnexpectedException()
        
        return self.get_current_line()
    
    def go_to_instruction_set_start(self):
        
        try:
            while True:
                m = re.search(r"Hexagon V5/V55 Programmer's Reference Manual\s*Instruction Set", self.current_line)
                if m:
                    print("Found start of Instruction Set at line: " + str(self.ln))
                    print(self.current_line)
                    break
                
                self.get_next_line()

        except self.OutOfLinesException:
            raise self.UnexpectedException()
    
    def find_econdings(self):
        try:
            inside_encoding = False
            inside_behavior = False
            
            last_syntax_found_ln = -1
            last_behavior_found_ln = -1
            while True:
                
                self.get_next_line()
                print(self.current_line)
                
                m = re.search(r"\s*Syntax\s*Behavior\s*", self.current_line)
                if m:
                    print("\nFound start of Syntax/Behavior at line: " + str(self.ln))
#                     print self.current_line
                    inside_behavior = True
                    continue
                
                m = re.search(r"^\s*Class: .*", self.current_line)
                if m:
                    print("\nFound start of Class at line: " + str(self.ln))
#                     print self.current_line
                    inside_behavior = False
                    continue
                
                m = re.search(r"\s*Encoding\s*", self.current_line)
                if m:
                    print("\nFound start of Encoding at line: " + str(self.ln))
#                     print self.current_line
                    inside_encoding = True
                    inside_behavior = False
                    continue
                
                # The end of an econding section is typically signaled by the start of the "Field name" section.
                m = re.search(r"Field name\s*Description", self.current_line)
                if m:
                    print("Found end of Encoding at line: " + str(self.ln) + '\n')
#                     print self.current_line
                    inside_encoding = False
                    inside_behavior = False
                    continue
                
                '''
                Syntax/Behavior extraction:
                Organized in two columns.
                '''
                if inside_behavior:
                    
                    
                    # Instructions without a clear separation of syntax and behavior are skipped
                    complicated_instructions = [
                        "Vector",
                        "Floating",
                        "Complex add/sub halfwords",
                        "Multiply",
                        "Shift by register",
                        "Set/clear/toggle bit",
                        "Extract bitfield",
                        "Test bit",
                        "CABAC decode bin",
                    ]
                    if True in [ci.lower() in self.current_inst_name.lower() for ci in complicated_instructions]:
                        continue
                    
                    
                    if self.current_line.strip() == '':
                            continue
                    
                    # Page header/footer skip
                    # TODO: maybe this should apply to more parts of the code, no just syntax/behavior
                    if ("Hexagon V5/V55 Programmer's Reference Manual" in self.current_line or
                        "MAY CONTAIN U.S. AND INTERNATIONAL EXPORT" in self.current_line or
                        "80-N2040-8 Rev. A" in self.current_line):
                        continue




                    # Try to match the 2 column format, basically tryng to see the separation space between them (the 5 spaces min requirement)
                    m = re.search(r"^\s*(\S.+?\S)\s{5,}(\S.+)", self.current_line)
                    if m:
                        print("Found pair of syntax/behavior")
                        print("Group 1: " + m.group(1))
                        print("Group 2: " + m.group(2))
                        behavior_1st_column_pos = m.start(1)
                        behavior_2nd_column_pos = m.start(2)
                        
#                         if self.current_line[0:behavior_2nd_column_pos].strip() != '':
#                             # Syntax column
#                             # TODO this if check should be include in the previous regex

                        # Continuation syntax (in 2 consecutive lines)
                        if self.ln - 1 == last_syntax_found_ln:
                            print("Cont Syntax: " + m.group(1))
                            self.syntax_behavior_text[-1][0] += " " + m.group(1)
                        else:
                            print("New Syntax: " + m.group(1))
                            self.syntax_behavior_text.append([m.group(1), ''])
                        last_syntax_found_ln = self.ln
                        
                        print("Behavior is: " + m.group(2))
                        self.syntax_behavior_text[-1][1] += m.group(2)
                        last_behavior_found_ln = self.ln
                    
                    else:
                        # Can be a behavior continuation line
                        if self.current_line[behavior_2nd_column_pos:].strip() != '':
                            if self.ln - 1 == last_behavior_found_ln:
                                print("Behavior cont is: " + self.current_line[behavior_2nd_column_pos:].strip())
                                self.syntax_behavior_text[-1][1] += self.current_line[behavior_2nd_column_pos:].strip()
                                last_behavior_found_ln = self.ln
                
                
                '''
                Start of a page of the "Instruction Set" section: if the first non empty line that appears
                in the next 3 to 5 lines (usually its 3 blank lines and the title)
                has text at the begining of the line, it's likely a new title, and hence a new instruction
                name. I'm assuming the title has at least 3 chars.
                
                TODO: Double line titles 
                ''' 
                m = re.search(r"Hexagon V5/V55 Programmer's Reference Manual\s*Instruction Set", self.current_line)
                if m:
#                     print "Found start of Instruction Set page at line: " + str(self.ln)
                    start_ln = self.ln
                    title_found = False
                    for _ in range(5):
                        self.get_next_line()
#                         print self.current_line
                        m = re.search(r"^\w{3}", self.current_line)
                        if m:
                            print("Found title at line: " + str(self.ln))
                            print(self.current_line)
                            self.current_inst_name = self.current_line.strip()
                            break
                    
                    # Just to be sure I return to where the search for a title began
                    if not title_found:
                        self.ln = start_ln 
                    
                    continue
                
                # The first four bits (ICLASS) of an encoding are always set (either to 0 or 1),
                # and are at the start of the line
                m = re.search(r"^([01]\s*){4}", self.current_line)
                if m:
#                     print "Found encoding at line: " + str(self.ln)
#                     print self.current_line
                    
                    # Bits not defined in the encoding are marked as "-", not left blank,
                    # so there is always 32 non-whites, particulary: 0/1, chars or "-".
                    m = re.search(r"^(([01a-zA-Z\-]\s*){32})(.*)$", self.current_line)
                    if m is None:
                        raise self.UnexpectedException()
                    
                    ie = m.group(1).replace(' ', '')
                    syntax = m.group(3) # My limited regex understanding doesn't get why this is the 3rd group and not the 2nd, but this works.
                    
                    # The syntax may be splitted in 2 lines, in this case the second line
                    # is all white spaces, until the position where the syntax started in the
                    # previous line, where the sytax string continues. Or can be the contrary,
                    # the second line of the syntax has the encoding and the first line is blank
                    next_line = self.peek_next_line()
                    prev_line = self.peek_prev_line()
                    
                    if len(next_line) > m.start(3) and re.search(r"^\s*$", next_line[0 : m.start(3)]): # all spaces up to the syntax string
                        # TODO: Change name m2.
                        m2 = re.search(r"^(\S.*)", next_line[m.start(3):]) # here has to be something (I can't specify what exactly besides a non space)
                        if m2:
                            print("Found syntax continuation")
                            print(("1st line: {:s}".format(syntax)))
                            print(("2nd line: {:s}".format(m2.group(1))))
                            
                            syntax += ' ' + m2.group(1)
                            
                            self.get_next_line() # To really pass over this continuation syntax line
                            
                    elif len(prev_line) > m.start(3) and re.search(r"^\s*$", prev_line[0 : m.start(3)]):
                        # TODO: Change name m2.
                        m2 = re.search(r"^(\S.*)", prev_line[m.start(3):]) # here has to be something (I can't specify what exactly besides a non space)
                        if m2:
                            print("Found syntax continuation in prev line")
                            print(("1st line: {:s}".format(m2.group(1))))
                            print(("2nd line: {:s}".format(syntax)))
                            
                            syntax = m2.group(1) + ' ' + syntax
                    
                    else:
                        # TODO: Tidy up.
                        # The same can happen but with a disalignment of the other syntax line (prev or next) by 1 char
                        if len(next_line) > (m.start(3) - 1) and re.search(r"^\s*$", next_line[0 : (m.start(3) - 1)]): # all spaces up to the syntax string
                            # TODO: Change name m2.
                            m2 = re.search(r"^(\S.*)", next_line[(m.start(3) - 1):]) # here has to be something (I can't specify what exactly besides a non space)
                            if m2:
                                print("Found syntax continuation")
                                print(("1st line: {:s}".format(syntax)))
                                print(("2nd line: {:s}".format(m2.group(1))))
                                
                                syntax += ' ' + m2.group(1)
                                
                                self.get_next_line() # To really pass over this continuation syntax line
                                
                        elif len(prev_line) > (m.start(3) - 1) and re.search(r"^\s*$", prev_line[0 : (m.start(3) - 1)]):
                            # TODO: Change name m2.
                            m2 = re.search(r"^(\S.*)", prev_line[(m.start(3) - 1):]) # here has to be something (I can't specify what exactly besides a non space)
                            if m2:
                                print("Found syntax continuation in prev line")
                                print(("1st line: {:s}".format(m2.group(1))))
                                print(("2nd line: {:s}".format(syntax)))
                                
                                syntax = m2.group(1) + ' ' + syntax

                            
                    print("Encoding: " + ie)
                    print("syntax:" + syntax)
                    
                    # TODO: handle instruction name
#                     if self.current_inst_name not in self.instructions:
#                         self.instructions[self.current_inst_name] = []

                    self.instructions.append(InstructionDefinition(syntax, ie))
                    
                    self.total_encodings += 1
                    
                    continue

            
        except ManualParser.OutOfLinesException:
            pass
#             print("End of scipt, out of lines")

        pass
    
    class OutOfLinesException(Exception):
        pass
        
    class UnexpectedException(Exception):
        pass
        
class HeaderParser:
    def __init__(self, header_fn):
        self.header = open(header_fn, 'r')
        self.lines = self.header.read().splitlines()

        self.duplex_inst_encodings = []
        self.other_inst_encodings = []
        
    def parse(self):
        for l in self.lines:
            
            # TODO: check out HEXAGON_MAPPING
            m = re.search(r'^HEXAGON_OPCODE \s* \( \s* " (.*)? " \s* , \s* " (.*)? "', l, re.X)
            if m:
                syntax = m.group(1)
                encoding = m.group(2).replace(' ', '')
                
                if len(encoding) != 32:
                    raise UnexpectedException
                
                # Split intructions: with subinsructions, marked with
                # 'EE' in the 15:14 (from rigth to left) position of their encoding, which
                # are going to be added to the database, and the rest, which only in the
                # case they were not already added from the manual will be included (this is
                # generally undocumented system instructions)
                
                if encoding[16:18].lower() == 'ee':
                    # I index the array from left to rigth, and just to be sure I'm converting to lower
                    encoding = (encoding[:16] + 
                                '00' +# 00 = Duplex type
                                encoding[18:])
                    self.duplex_inst_encodings.append(InstructionDefinition(syntax, encoding))
                else:
                    self.other_inst_encodings.append(InstructionDefinition(syntax, encoding))
#                     print("syntax: " + syntax)
#                     print("encoding: " + encoding)
                    
    def standarize_syntax(self, encodings):
        # To make it look like the manual
        
        for i in range(len(encodings)):
            syntax = encodings[i].syntax
            
            # Remove registers size (I'm assuming) from their name:
            # Rd16 -> Rd
#             print("Before: " + syntax)
            syntax = re.sub(r'\b ([RPNMCGS][a-z]{1,2}) \d{0,2} \b', r'\1', syntax, flags = re.X) # TODO: Register all possible register types, s,r,t,e etc.
#             print("After: " + syntax)
            
            encodings[i].syntax = syntax
        
def exapand_one_char_opt(syntax_behavior_in, opt_syntax):
    expanded = []
    for sb in syntax_behavior_in:
        syntax = sb[0]
        behavior = sb[1]
        if opt_syntax not in syntax:
            expanded.append(sb)
            continue
        
        if opt_syntax not in behavior:
            # TODO: different opt strings
            expanded.append(sb)
            continue

        print("Optional {:s} found: ".format(opt_syntax) + syntax)
        
        opt_chars = list(opt_syntax[1:-1]) # remove '[]'
        if len(opt_chars) == 1:
            opt_chars.append('') # only 1 char, [!] case, it's a possibility to remove it
            
            for c in opt_chars:
                new_syntax = syntax.replace(opt_syntax, c)
                new_behavior = behavior.replace(opt_syntax, c)
                print("Expanded: " + new_syntax)
                print("Expanded: " + new_behavior)
                expanded.append((new_syntax, new_behavior))
    
    return expanded
                            
def exapand_string_opt(syntax_behavior_in, opt_str):
    expanded = []
    for sb in syntax_behavior_in:
        syntax = sb[0]
        behavior = sb[1]
        if opt_str not in syntax:
            expanded.append(sb)
            continue
        
        if opt_str not in behavior:
            # TODO: different opt strings
            expanded.append(sb)
            continue
        
        print("Optional {:s} found: ".format(opt_str) + syntax)
        
        opt_str_values = [opt_str[1:-1], # remove '[]'
                          '']
        for s in opt_str_values:
            new_syntax = syntax.replace(opt_str, s)
            new_behavior = behavior.replace(opt_str, s)
            print("Expanded: " + new_syntax)
            print("Expanded: " + new_behavior)
            expanded.append((new_syntax, new_behavior))
    
    return expanded
                            
        
if __name__ == "__main__":
    
    mp = ManualParser('../inst_sources/programmers_ref_v5.txt')
    
    mp.go_to_instruction_set_start()
    
    mp.find_econdings()
    
    # In the first complete search I've found 244 instructions and 1424 encodings, this values shouldn't change.
    # TODO: handle instruction names
#     if len(pm.instructions) != 244:
#         raise ParsedManual.UnexpectedException()
    if mp.total_encodings != 1424:
        raise ManualParser.UnexpectedException()
    
#     print(("Found {:d} instructions.".format(len(pm.instructions))))
    print(("Found {:d} encodings.".format(mp.total_encodings)))
    
    # Include header file duplex instructions, and other unknown instructions
    hp = HeaderParser('../inst_sources/hexagon_iset_v5.h')
    hp.parse()
    
    hp.standarize_syntax(hp.duplex_inst_encodings)
    hp.standarize_syntax(hp.other_inst_encodings)
    # TODO: should be done during parsing, not here
    
    mp.instructions.extend(hp.duplex_inst_encodings)
    
    # add only unknown instructions
    other_inst_added = 0
    for other_inst in hp.other_inst_encodings:
        encoding_found = False
        for known_inst in mp.instructions:
            if known_inst.encoding.mask == other_inst.encoding.mask and known_inst.encoding.value == other_inst.encoding.value:
                # TODO: this comparison shuld be part of the instructionEncoding class
                encoding_found = True
                break
            
        if encoding_found == False:
            mp.instructions.append(other_inst)
            other_inst_added += 1
#             print("added: " + other_inst.syntax)

    print("Added extra {:d} encodings, total: {:d}".format(len(hp.duplex_inst_encodings) + other_inst_added, len(mp.instructions)))

    # Syntax / Behavior
    print("Syntax/Behavior Found")
    for sb in mp.syntax_behavior_text:
        print(sb[0].ljust(20))
        print('-' * 20)
        print(sb[1].replace(';', ';\n'))
    
    print(("Found {:d} syntax.".format(len(mp.syntax_behavior_text))))
    
    # pickle_dump('../data/behavior_raw.pkl', pm.syntax_behavior_text)
    # TODO: add behavior path
    
    
    
    # Optional syntax symbols
    # TODO: Deal with these, expand them.
    print("\nOptional symbols in syntax")
    opt_symbos = []
    for sb in mp.syntax_behavior_text:
        syntax = sb[0]
        for i in range(len(syntax)):
            if syntax[i] == '[':
                start = i
                end = i
                while syntax[end] != ']':
                    end += 1
                opt = syntax[start:end+1]
                if opt == '[0]':
                    print(syntax)
                if opt not in opt_symbos:
                    print(syntax[start:end+1])
                    opt_symbos.append(opt)
    
    # Expand optional symbols
    # [HL]
    # [!]
    # [.new]
    # [01]
    # [+-]
    # [+-|&]
    # [:sat]
    # [&|^]
    # [&|]
    one_char_options = ['[!]', '[01]', '[+-]', '[+-|&]', '[&|^]', '[&|]']
    # TODO: '[HL]' maps in the behavior like [01], deal with that
    expanded_syntax_behavior = []
    for sb in mp.syntax_behavior_text:
 
        sb_expanded = [sb]
        for opt_syntax in one_char_options:
            sb_expanded = exapand_one_char_opt(sb_expanded, opt_syntax)
         
        sb_expanded = exapand_string_opt(sb_expanded, '[.new]')
        sb_expanded = exapand_string_opt(sb_expanded, '[:sat]')
         
        expanded_syntax_behavior.extend(sb_expanded)
         
    mp.syntax_behavior_text = expanded_syntax_behavior
    
    # TODO: <hint> in the syntax of some behaviors has to be expanded to :t and :nt




    # TODO: match the behavior to the syntax, to have it all in one structure/array
    match_behaviors = 0
    for inst_def in mp.instructions:
        syntax = inst_def.syntax
        encoding = inst_def.encoding
        print("syntax: " + syntax)
        print("encoding: " + encoding.text)
        
        syntax_to_match = syntax.lower().replace(' ', '')
        
        # TODO: very inefficient, inner for
        for sb in mp.syntax_behavior_text:
            syntax_2 = sb[0]
            behavior = sb[1]
            
            syntax_2 = syntax_2.lower().replace(' ', '')
            
            if syntax_to_match == syntax_2:
                match_behaviors += 1
                print("SYNTAX MATCH!!")
                print(syntax_2.ljust(20))
                print('-' * 20)
                print(behavior.replace(';', ';\n'))
                inst_def.behavior = behavior
                break
    
    print('Match behavior: {0:.2f}%'.format(match_behaviors / len(mp.syntax_behavior_text) * 100))

    # TODO: Add corrected_behaviors.py to the repo.
#     # Apply corrected behaviors specified in the behaviors script:
#     sys.path.append('../inst_sources/')
#     from behaviors_annex import corrected_behaviors
#     # TODO: figure out how to include this script, or make it into a pickle binary file and just load it
#     for sb in corrected_behaviors:
#         syntax = sb[0]
#         behavior = sb[1]
#         syntax = syntax.lower().replace(' ', '')
#         found_syntax = False
# #         pv('syntax')
#         for inst_def in mp.instructions:
#             syntax_to_match = inst_def.syntax.lower().replace(' ', '')
# #             pv('syntax_to_match')
#             if syntax_to_match == syntax:
#                 inst_def.behavior = behavior
#                 found_syntax = True
#                 break
#
#         if found_syntax == False:
#             # All of these corrected behaviors should match
#             raise UnexpectedException()
    

    pickle_dump(INST_DEF_PATH, mp.instructions)
