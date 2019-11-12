def handle_instruction(instruction):
    if instruction['ast_type'] == "BinOp":
        print("deal with BinOp operation here")
        handleBinOp(instruction)
    elif instruction['ast_type'] == "Constant":
        print("deal with Constant operation here")
    elif instruction['ast_type'] == "Expr":
        print("deal with Expr operation here")
        handleExpr(instruction)
    elif instruction['ast_type'] == "Num":
        print("deal with Num operation here")
        #handleNum(instruction)
    elif instruction['ast_type'] == "Name":
        print("deal with Name operation here")
        #handleName(instruction)
    elif instruction['ast_type'] == "Assign":
        print("deal with Assign operation here")
        # handleAssign(instruction)


def handleExpr(instruction):
    handle_instruction(instruction['value'])

def handleBinOp(instruction):
        handle_instruction(instruction['right'])
        handle_instruction(instruction['left'])

class Searcher:

    def __init__(self, instructions, vulnerabilities):
        # Store the found variables as key | value. key is the variable name and value is if it's untainted
        self.variables = dict()
        self.vulnerabilities = vulnerabilities
        # self.flows = list() we might use this later

        for inst in instructions:
            handle_instruction(inst)

    # Here we need to make a function for each operation, like binary operations, func calls, etc..
