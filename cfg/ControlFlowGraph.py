from cfg.BasicBlock import BasicBlock


class ControlFlowGraph:

    def __init__(self, instructions):
        self.basicBlocks = list()
        self.get_basic_blocks(instructions)


    def __repr__(self):
        toReturn = '[\n'
        for x in self.basicBlocks:
            toReturn += "{0},\n".format(x)
        toReturn += ']'
        return toReturn


    def get_basic_blocks(self, instructions):

        # TODO: Append the entry node

        # Iterate through the instructions and make the basic blocks
        #TODO: BE CAREFULL WITH THE SPECIAL CASES LIKE IF WE HAVE A BREAK IN THE MIDDLE OF A LOOP
        current_basic_block = None
        for instr in instructions:
            if current_basic_block is None:
                current_basic_block = BasicBlock()
                current_basic_block.add_instruction(instr)
            elif current_basic_block and instr.leader:
                self.basicBlocks.append(current_basic_block)
                current_basic_block = BasicBlock()
                current_basic_block.add_instruction(instr)
            else:
                current_basic_block.add_instruction(instr)

        # Add the last basic block
        if current_basic_block is not None:
            self.basicBlocks.append(current_basic_block)

        # TODO: Append the exit node

        print(self)
