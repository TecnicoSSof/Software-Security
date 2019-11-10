class Instruction:
    conditional_ast_operators = ['If', 'While', 'For']
    conditional_loop_operators = ['While', 'For']

    def __init__(self, ast_type, line):
        # TODO: Add more information if needed
        self.ast_type = ast_type
        self.line = line
        self.leader = False

    def __repr__(self):
        return "{0} - {1}\n".format(self.ast_type, self.line)

    def is_condition(self):
        return self.ast_type in self.conditional_ast_operators

    @staticmethod
    def parse_json_to_instructions(json_instructions):
        instructions = list()
        next_instruction_is_leader = False

        for instruction in json_instructions:
            # Append the main instruction
            new_instruction = Instruction(instruction['ast_type'], instruction['lineno'])

            # If an instruction is the target of a conditional jump or unconditional jump
            if instruction['ast_type'] in Instruction.conditional_loop_operators:
                new_instruction.leader = True
                next_instruction_is_leader = True
            elif next_instruction_is_leader:
                new_instruction.leader = True
                next_instruction_is_leader = False

            instructions.append(new_instruction)

            if instruction['ast_type'] in Instruction.conditional_ast_operators:
                iteration = 0
                for i in Instruction.parse_json_to_instructions(instruction['body']):
                    # Any instruction that immediately follows a conditional or unconditional jump is a leader
                    if iteration == 0:
                        i.leader = True
                    instructions.append(i)
                    iteration += 1

                iteration = 0
                for i in Instruction.parse_json_to_instructions(instruction['orelse']):
                    # Any instruction that immediately follows a conditional or unconditional jump is a leader
                    if iteration == 0:
                        i.leader = True
                    instructions.append(i)
                    iteration += 1

        return instructions
