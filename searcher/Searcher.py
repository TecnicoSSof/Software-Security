from searcher.VulnNode import VulnNode
from searcher.VulnerabilitySpec import VulnerabilitySpec


class Searcher:

    def __init__(self, instructions, vulnerabilities):
        self.vulnerabilities = vulnerabilities
        self.declared_variables = list()
        self.vulnNodes = list()

        # self.flows = list() we might use this later

        for inst in instructions:
            self.handle_instruction(inst)

        print(self.vulnNodes)

    # Here we need to make a function for each operation, like binary operations, func calls, etc..
    def handle_instruction(self, instruction):
        if instruction['ast_type'] == "BinOp":
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
        # handling right side
        used_vars = self.handle_instruction(instruction['value'])
        for var in used_vars:
            if var[1] == "var" and var not in self.declared_variables:
                self.declared_variables.append(var)
                vulnList = []
                for vuln in self.vulnerabilities:
                    vulnList.append(VulnerabilitySpec(vuln.name, []))
                self.vulnNodes.append(VulnNode(var, var, vulnList))

        # TODO check if func call is tainted? to taint var

        # handling left
        for i in range(len(instruction['targets'])):
            taint = False
            current_var = self.handle_instruction(instruction['targets'][i])[0]
            # check if any of the variables are tainted or untainted to assign the new variable state

            for vuln in self.vulnNodes:
                for var in used_vars:
                    if var == vuln.varName:
                        taint = True
                        for vulnIsSelf in self.vulnNodes:
                            if vulnIsSelf.varName == current_var:
                                self.vulnNodes.remove(vulnIsSelf)
                        self.vulnNodes.append(VulnNode(vuln.source, current_var, vuln.vulnerabilies))
                        break

            # if the targets are not yet in the declared variables add them
            if current_var not in self.declared_variables:
                self.declared_variables.append(current_var)

            #     if not tainted anymore
            if taint!=True:
                for vuln in self.vulnNodes:
                    for var in used_vars:
                        if var == vuln.varName:
                            taint = True
                            self.vulnNodes.remove(vuln)

    def handleNum(self, instruction):
        print("this cannot be tainted, so skip")
        return []

    def handleName(self, instruction):
        # return the variable name as an array to be handled by the callee functions
        return [(instruction['id'], "var")]

    def handleFuncName(self, instruction):
        return [(instruction['id'], "func")]

    def handleCall(self, instruction, args):
        handledArgs = list()
        for i in range(len(args)):
            handledArgs = self.handle_instruction(args[i])
        funcName = self.handleFuncName(instruction['func'])
        # for arg in handledArgs:
        #     if(arg[1]=='var'):
        #         for node in self.vulnNodes:
        #             if node.source
        #         sinks = self.checkSinks(funcName)

        #TODO here sth if funcname is vuln sink then lookup args ???
        #TODO here sth if funcname is vuln source then tain left? or return name and lookup in assign?

    # def checkSinks(self, funcName):
    #     vulnerabilites = list()
    #     for vuln in self.vulnerabilities:
    #         for source in vuln.sinks:
    #             if funcName == source:
    #                 vulnerabilites.append((vuln.name, sink))


