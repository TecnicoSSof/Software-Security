def print_vulnerability(name, func_name, arg):
    print('{"vulnerability":"', end="")
    print(name + '",')
    print('"source":"', end="")
    print(arg[1] if (arg[1] is not None) else "", end="\",\n")
    print('"sink":"', end="")
    print(func_name + '",')
    print('"sanitizer":"', end="")
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
        elif instruction['ast_type'] == "Num" or instruction['ast_type'] == "Constant":
            return []

    def handle_expr(self, instruction):
        return self.handle_instruction(instruction['value'])

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
        target_vars = []
        used_vars = self.handle_instruction(instruction['value'])
        self.update_declared_variables_and_taint(used_vars)
        for i in range(len(instruction['targets'])):
            var_name = self.handle_instruction(instruction['targets'][i])[0]
            target_vars.append(var_name)
            # check if any of the variables are tainted or untainted to assign the new variable state
            for vuln in self.vulnerabilities:
                tainted = False
                var = None
                current_sanitizer = None
                for var in used_vars:
                    if (var in vuln.variables and vuln.variables[var][0]) or var in vuln.sources:
                        # assign the new variable state
                        if vuln.variables and vuln.variables[var][0]:
                            current_sanitizer = vuln.variables[var][2]
                        tainted = True
                vuln.variables[var_name] = (tainted, var, current_sanitizer)

            # if the targets are not yet in the declared variables add them
            if var_name not in self.declared_variables:
                self.declared_variables.append(var_name)
        return target_vars

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
        self.update_declared_variables_and_taint(handled_args)

        # check if the func name is a sanitizer, if so, set variables to untainted.
        for vuln in self.vulnerabilities:
            if func_name in vuln.sanitizers:
                for arg in handled_args:
                    # any_variable_in_sanitizer_is_tainted = False
                    if arg in vuln.variables:
                        # any_variable_in_sanitizer_is_tainted = True
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
        handled_vars = self.get_new_vars_from_json(instruction, 'body')
        for var in self.get_new_vars_from_json(instruction, 'orelse'):
            handled_vars.append(var)

        # if any of the tested variables is tainted, it may be possible to exist an implicit flow. its better to warn
        # them, than if not warn them, so it may produce false positives. There are no perfect tools :D
        self.taint_implicits(handled_comparison_vars, handled_vars)

    def handle_loop(self, instruction):
        handled_comparison_vars = self.handle_instruction(instruction['test'])
        handled_vars = self.get_new_vars_from_json(instruction, 'body')

        # if any of the tested variables is tainted, it may be possible to exist an implicit flow. its better to warn
        # them, than if not warn them, so it may produce false positives. There are no perfect tools :D
        self.taint_implicits(handled_comparison_vars, handled_vars)

    def update_declared_variables_and_taint(self, variables):
        for var in variables:
            if var not in self.declared_variables:
                self.declared_variables.append(var)
                for vuln in self.vulnerabilities:
                    vuln.variables[var] = (True, var, None)

    def taint_implicits(self, handled_comparison_vars, handled_vars):
        for vuln in self.vulnerabilities:
            any_tainted_variable = False
            current_sanitizer = None
            current_source = None
            for var in handled_comparison_vars:
                if vuln.variables[var]:
                    any_tainted_variable = True
                    current_source = vuln.variables[var][1]
                    current_sanitizer = vuln.variables[var][2]
            if any_tainted_variable:
                for var in handled_vars:
                    vuln.variables[var] = (True, current_source, current_sanitizer)

    def get_new_vars_from_json(self, instruction, param):
        handled_vars = []

        for instruct in instruction[param]:
            new_vars = self.handle_instruction(instruct)
            for var in new_vars:
                if var not in handled_vars:
                    handled_vars.append(var)

        return handled_vars
