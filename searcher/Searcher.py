def getStr(list):
    toret = ""
    for x in list:
        toret += x + "\n"
    return toret

class Searcher:

    def __init__(self, instructions, vulnerabilities):
        self.vulnerabilities = vulnerabilities
        self.declared_variables = list()
        self.current_condition_vars_stack = list()
        self.output = list()

        for inst in instructions:
            self.handle_instruction(inst)

    # Here we need to make a function for each operation, like binary operations, func calls, etc..
    def handle_instruction(self, instruction):
        if instruction['ast_type'] == "UnaryOp":
            return self.handle_unary_op(instruction)
        elif instruction['ast_type'] == "BinOp":
            return self.handle_bin_op(instruction)
        elif instruction['ast_type'] == "Expr":
            return self.handle_expr(instruction)
        elif instruction['ast_type'] == "Name":
            return self.handle_name(instruction)
        elif instruction['ast_type'] == "Attribute":
            return self.handle_attribute(instruction)
        elif instruction['ast_type'] == "Assign":
            return self.handle_assign(instruction)
        elif instruction['ast_type'] == 'While':
            return self.handle_loop(instruction)
        elif instruction['ast_type'] == "If":
            return self.handle_condition(instruction)
        elif instruction['ast_type'] == "Compare":
            return self.handle_compare(instruction)
        elif instruction['ast_type'] == "Call":
            return self.handle_call(instruction, instruction['args'])
        elif instruction['ast_type'] == "Tuple":
            return self.handle_tuple(instruction)
        elif instruction['ast_type'] == "Num" or instruction['ast_type'] == "Constant":
            return []
        elif instruction['ast_type'] == "NameConstant" or instruction['ast_type'] == "Str":
            return []
        else:
            print("Something went wrong the unsupported type of operation: " + instruction['ast_type'])

    def print_vulnerability(self, name, func_name, arg):
        to_return = '{"vulnerability":"' + name + '",\n' + '"source":"'
        if arg[1] is not None:
            to_return = to_return + arg[1]
        to_return = to_return + "\",\n" + '"sink":"' + func_name + '",\n' + '"sanitizer":"'
        if arg[2] is not None:
            to_return = to_return + arg[2]
        to_return = to_return + '"}'
        self.output.append(to_return)
        # print(to_return)
        # print('{"vulnerability":"', end="")
        # print(name + '",')
        # print('"source":"', end="")
        # print(arg[1] if (arg[1] is not None) else "", end="\",\n")
        # print('"sink":"', end="")
        # print(func_name + '",')
        # print('"sanitizer":"', end="")
        # print(arg[2] if (arg[2] is not None) else "", end="")
        # print('"}')

    def handle_expr(self, instruction):
        return self.handle_instruction(instruction['value'])

    def handle_unary_op(self, instruction):
        return self.handle_instruction(instruction['operand'])

    def handle_bin_op(self, instruction):
        part1 = self.handle_instruction(instruction['left'])
        part2 = self.handle_instruction(instruction['right'])
        to_return = []
        if part1 is not None:
            to_return = part1
        if part2 is not None:
            to_return.extend(part2)
        return to_return

    def handle_assign(self, instruction):
        used_vars = self.handle_instruction(instruction['value'])
        self.update_declared_variables_and_taint(used_vars)
        for i in range(len(instruction['targets'])):
            var_name = self.handle_instruction(instruction['targets'][i])[0]
            # check if any of the variables are tainted or untainted to assign the new variable state
            for vuln in self.vulnerabilities:
                tainted = False
                var = None
                current_sanitizer = None
                current_taint = None
                for var in used_vars:
                    if var in vuln.variables and vuln.variables[var][0]:
                        # assign the new variable state
                        if var in vuln.variables and vuln.variables[var][0]:
                            current_sanitizer = vuln.variables[var][2]
                            if vuln.variables[var][1] is not None:
                                current_taint = vuln.variables[var][1]
                        tainted = True
                    elif var in vuln.sources:
                        tainted = True

                if not tainted:
                    # here we are going to check if there is any tainted variable on a certain vulnerability on the
                    # conditions it means we are on a conditional context so there can be implicit flows
                    for var_cond in self.current_condition_vars_stack:
                        if var_cond in vuln.variables and vuln.variables[var_cond][0]:
                            current_sanitizer = vuln.variables[var_cond][2]
                            tainted = True
                        elif var_cond in vuln.sources:
                            tainted = True
                    vuln.variables[var_name] = (tainted, var_name, current_sanitizer)
                else:
                    if current_taint is not None:
                        vuln.variables[var_name] = (tainted, current_taint, current_sanitizer)
                    else:
                        vuln.variables[var_name] = (tainted, var, current_sanitizer)


            # if the targets are not yet in the declared variables add them
            if var_name not in self.declared_variables:
                self.declared_variables.append(var_name)
        return []

    def handle_name(self, instruction):
        # return the variable name as an array to be handled by the callee functions
        return [instruction['id']]

    def handle_attribute(self, instruction):
        return [instruction['attr']]

    def handle_call(self, instruction, args):
        handled_args = list()
        for i in range(len(args)):
            temp = self.handle_instruction(args[i])
            if temp:
                handled_args.extend(temp)
        func_name = self.handle_instruction(instruction['func'])[0]
        self.update_declared_variables_and_taint(handled_args, func_name)

        # check if the func name is a sanitizer, if so, set variables to untainted.
        for vuln in self.vulnerabilities:
            if func_name in vuln.sanitizers:
                for arg in handled_args:
                    if arg in vuln.variables:
                        vuln.variables[arg] = (vuln.variables[arg][0], vuln.variables[arg][1], func_name)

            # check if the func name is a sink, if so, check if the arg is tainted, if so, set it as a vulnerability
            elif func_name in vuln.sinks:
                # check if the condition is tainted, check if there is any argument of the function that is not a
                # sanitizer
                tainted_condition = False
                for var_cond in self.current_condition_vars_stack:
                    if (var_cond in vuln.variables and vuln.variables[var_cond][0]) or var_cond in vuln.sources:
                        tainted_condition = True

                if tainted_condition:
                    for arg in handled_args:
                        if arg not in vuln.sanitizers:
                            self.print_vulnerability(vuln.name, func_name, vuln.variables[arg])
                else:
                    for arg in handled_args:
                        if arg in vuln.variables and vuln.variables[arg][0]:
                            self.print_vulnerability(vuln.name, func_name, vuln.variables[arg])
            else:
                for arg in handled_args:
                    if arg in vuln.variables and vuln.variables[arg][0]:
                        vuln.variables[func_name] = (True, func_name, vuln.variables[arg][2])

        return [func_name] + handled_args

    def handle_compare(self, instruction):
        comparator_variables = []
        # get variables inside comparators
        for i in instruction['comparators']:
            instruction_variables = self.handle_instruction(i)
            if len(instruction_variables):
                comparator_variables += instruction_variables

        # get variables inside the left part
        instruction_variable = self.handle_instruction(instruction['left'])
        if len(instruction_variable):
            comparator_variables += instruction_variable

        return comparator_variables

    def handle_condition(self, instruction):
        handled_comparison_vars = self.handle_instruction(instruction['test'])
        self.current_condition_vars_stack += handled_comparison_vars

        for instruct in instruction['body']:
            new_vars = self.handle_instruction(instruct)

        for instruct in instruction['orelse']:
            new_vars = self.handle_instruction(instruct)

        # print(">> ", self.current_condition_vars_stack)
        # TODO PLACE THIS IN ASSIGNS AND FUNCTION CALLS
        # if any of the tested variables is tainted, it may be possible to exist an implicit flow. its better to warn
        # them, than if not warn them, so it may produce false positives. There are no perfect tools :D
        # self.taint_implicits(handled_comparison_vars, [])

        # remove from the used variables on stack = self.current_condition_vars_stack
        for i in handled_comparison_vars: self.current_condition_vars_stack.pop()
        return []

    def handle_loop(self, instruction):
        handled_comparison_vars = self.handle_instruction(instruction['test'])
        self.current_condition_vars_stack += handled_comparison_vars

        for instruct in instruction['body']:
            new_vars = self.handle_instruction(instruct)

        # remove from the used variables on stack = self.current_condition_vars_stack
        for i in handled_comparison_vars: self.current_condition_vars_stack.pop()
        return []

    def handle_tuple(self, instruction):
        to_return = []
        for ins in instruction['elts']:
            handled = self.handle_instruction(ins)
            if handled is not None:
                to_return.extend(handled)
        return to_return

    def update_declared_variables_and_taint(self, variables, func_name=None):
        if len(variables) == 0 or func_name is not None:
            self.declared_variables.append(func_name)
            for vuln in self.vulnerabilities:
                if func_name in vuln.sources:
                    vuln.variables[func_name] = (True, func_name, None)

        for var in variables:
            if var not in self.declared_variables:
                self.declared_variables.append(var)
                for vuln in self.vulnerabilities:
                    if var not in vuln.sinks and var not in vuln.sanitizers:
                        vuln.variables[var] = (True, var, None)

    def taint_implicits(self, handled_comparison_vars, handled_vars):
        for vuln in self.vulnerabilities:
            any_tainted_variable = False
            current_sanitizer = None
            current_source = None
            for var in handled_comparison_vars:
                if vuln.variables[var] and vuln.variables[var][0]:
                    any_tainted_variable = True
                    current_source = vuln.variables[var][1]
                    current_sanitizer = vuln.variables[var][2]
            if any_tainted_variable:
                for var in handled_vars:
                    vuln.variables[var] = (True, current_source, current_sanitizer)
