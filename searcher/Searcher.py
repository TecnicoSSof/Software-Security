class Searcher:

    def __init__(self, instructions, vulnerabilities):
        self.vulnerabilities = vulnerabilities
        self.declared_variables = list()

        # self.flows = list() we might use this later

        for inst in instructions:
            self.handle_instruction(inst)

        print(self.declared_variables)

    # Here we need to make a function for each operation, like binary operations, func calls, etc..
    def handle_instruction(self, instruction):
        if instruction['ast_type'] == "BinOp":
            print("deal with BinOp operation here")
            return self.handleBinOp(instruction)
        elif instruction['ast_type'] == "Expr":
            return self.handleExpr(instruction)
        elif instruction['ast_type'] == "Num":
            return self.handleNum(instruction)
        elif instruction['ast_type'] == "Name":
            return self.handleName(instruction)
        elif instruction['ast_type'] == "Assign":
            return self.handleAssign(instruction)
        elif instruction['ast_type'] == "Call":
            print("deal with Call operation here")
            return self.handleCall(instruction, instruction['args'])
        elif instruction['ast_type'] == "Constant":
            return []

    def handleExpr(self, instruction):
        self.handle_instruction(instruction['value'])

    def handleBinOp(self, instruction):
        part1 = self.handle_instruction(instruction['left'])
        part2 = self.handle_instruction(instruction['right'])
        return part1 + part2

    def handleAssign(self, instruction):
        used_vars = self.handle_instruction(instruction['value'])
        for var in used_vars:
            if var not in self.declared_variables:
                self.declared_variables.append(var)
                for vuln in self.vulnerabilities:
                    vuln.variables[var] = True

        for i in range(len(instruction['targets'])):
            var_name = self.handle_instruction(instruction['targets'][i])[0]
            # check if any of the variables are tainted or untainted to assign the new variable state
            for vuln in self.vulnerabilities:
                tainted = False
                for var in used_vars:
                    if var in vuln.variables and vuln.variables[var]:
                        # assign the new variable state
                        tainted = True
                        break
                vuln.variables[var_name] = tainted

            # if the targets are not yet in the declared variables add them
            if var_name not in self.declared_variables:
                self.declared_variables.append(var_name)

    def handleNum(self, instruction):
        print("this cannot be tainted, so skip")
        return []

    def handleName(self, instruction):
        # return the variable name as an array to be handled by the callee functions
        return [instruction['id']]

    def handleFuncName(self, instruction):
        print("this is a function: " + instruction['id'])

    def handleCall(self, instruction, args):
        for i in range(len(args)):
            self.handle_instruction(args[i])
        self.handleFuncName(instruction['func'])
