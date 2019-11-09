class ControlFlowGraph:

    def __init__(self, instructions):
        self.instructions = instructions
        self.basicBlocks = list()
        self.build()

    def build(self):
        # Get Leaders
        self.get_leaders()
        self.getBasicBlocks()

    def get_leaders(self):
        print("get leaders, set them to true or save them in a list and use that list to compare if the block is there")

    def get_basic_blocks(self):
        # Iterate through the instructions and check which ones are leaders
        print("get basic blocks from the set of instructions")
