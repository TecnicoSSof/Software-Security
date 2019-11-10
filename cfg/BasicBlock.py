class BasicBlock:

    def __init__(self):
        #TODO: SET THE ENTRY AND EXIT BLOCK
        self.instructions = list()

    def __repr__(self):
        return "{0}\n".format(self.instructions)

    def add_instruction(self, instruction):
        self.instructions.append(instruction)
