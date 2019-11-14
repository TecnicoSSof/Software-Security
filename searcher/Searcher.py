def print_vulnerability(name, func_name, arg):
    print('{"vulnerability": "', end="")
    print(name + '",')
    print('"source": "', end="")
    print(arg[1] if (arg[1] is not None) else "", end="\"\n")
    print('"sink": "', end="")
    print(func_name + '",')
    print('"sanitizer": "', end="")
    print(arg[2] if (arg[2] is not None) else "", end="")
    print('"}')


class Searcher:

    def __init__(self, instructions, vulnerabilities):
        self.vulnerabilities = vulnerabilities
        self.declared_variables = list()

        for inst in instructions:
            self.handle_instruction(inst)

    # Here we need to make a function for each operation, like binary operations, func calls, etc..
    def handle_instruction(self, instruction):
        if instruction['ast_type'] == "BinOp":
            return self.handle_bin_op(instruction)
        elif instruction['ast_type'] == "Expr":
            return self.handle_expr(instruction)
        elif instruction['ast_type'] == "Name":
            return self.handle_name(instruction)
        elif instruction['ast_type'] == "Assign":
            return self.handle_assign(instruction)
        elif instruction['ast_type'] == "Call":
            return self.handle_call(instruction, instruction['args'])
        elif instruction['ast_type'] == "Num" or instruction['ast_type'] == "Constant":
            return []

    def handle_expr(self, instruction):
        self.handle_instruction(instruction['value'])

    def handle_bin_op(self, instruction):
        part1 = self.handle_instruction(instruction['left'])
        part2 = self.handle_instruction(instruction['right'])
        return part1 + part2

    def update_declared_variables_and_taint(self, variables):
        for var in variables:
            if var not in self.declared_variables:
                self.declared_variables.append(var)
                for vuln in self.vulnerabilities:
                    vuln.variables[var] = (True, var, None)


    def handle_assign(self, instruction):
        used_vars = self.handle_instruction(instruction['value'])
        self.update_declared_variables_and_taint(used_vars)
        for i in range(len(instruction['targets'])):
            var_name = self.handle_instruction(instruction['targets'][i])[0]
            # check if any of the variables are tainted or untainted to assign the new variable state
            for vuln in self.vulnerabilities:
                tainted = False
                var = None
                for var in used_vars:
                    if (var in vuln.variables and vuln.variables[var][0]) or var in vuln.sources:
                        # assign the new variable state
                        tainted = True
                        break
                vuln.variables[var_name] = (tainted, var, None)

            # if the targets are not yet in the declared variables add them
            if var_name not in self.declared_variables:
                self.declared_variables.append(var_name)

    def handle_name(self, instruction):
        # return the variable name as an array to be handled by the callee functions
        return [instruction['id']]

    def handle_call(self, instruction, args):
        handled_args = list()
        for i in range(len(args)):
            handled_args = self.handle_instruction(args[i])
        func_name = instruction['func']['id']
        self.update_declared_variables_and_taint(handled_args)

        # check if the func name is a sanitizer, if so, set variables to untainted. todo check if it works
        for vuln in self.vulnerabilities:
            if func_name in vuln.sanitizers:
                for arg in handled_args:
                    any_variable_in_sanitizer_is_tainted = False
                    if arg in vuln.variables:
                        any_variable_in_sanitizer_is_tainted = True
                        # dont make false, make still tainted just add to sanitz
                        # vuln.variables[arg][0] = False
                        vuln.variables[arg] = (vuln.variables[arg][0], vuln.variables[arg][1], func_name)
                    # Append into the used sanitizers, needed for output
                    # if any_variable_in_sanitizer_is_tainted:
                    #     vuln.used_sanitizers.append(func_name)

            # check if the func name is a sink, if so, check if the arg is tainted, if so, set it as a vulnerability
            elif func_name in vuln.sinks:
                for arg in handled_args:
                    if arg in vuln.variables and vuln.variables[arg][0]:
                        print_vulnerability(vuln.name, func_name, vuln.variables[arg])

        return [func_name] + handled_args
