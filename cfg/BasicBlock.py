class BasicBlock:

    def __init__(self):
        # TODO: SET THE ENTRY AND EXIT BLOCK
        self.instructions = list()

    def __repr__(self):
        toReturn = ''
        for x in self.instructions:
            toReturn += "\t" + "[{0}]".format(x)
        return toReturn

    def add_instruction(self, instruction):
        self.instructions.append(instruction)
