class Searcher:

    def __init__(self, instructions, vulnerabilities):
        # Store the found variables as key | value. key is the variable name and value is if it's untainted
        self.variables = dict()
        self.vulnerabilities = vulnerabilities
        # self.flows = list() we might use this later

        for inst in instructions:
            self.handle_instruction(inst)

    def handle_instruction(self, instruction):
        if instruction['ast_type'] == "binOp":
            print("deal with binary operation here")
            # handleBinOp(instruction)
        elif instruction['ast_type'] == "Constant":
            print("deal with Constant operation here")
            # handleConstant(instruction)
        elif instruction['ast_type'] == "Assign":
            print("deal with Assign operation here")
            # handleAssign(instruction)

    # Here we need to make a function for each operation, like binary operations, func calls, etc..
