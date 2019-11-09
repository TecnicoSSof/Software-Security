class BasicBlock:

    def __init__(self, instructions):
        #TODO: SET THE ENTRY AND EXIT BLOCK
        self.entry_block = False
        self.instructions = instructions
        self.exit_block = False
