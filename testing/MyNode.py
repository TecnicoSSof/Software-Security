vulnerabilities = list()
taintedVars = list()
vars = list()


def getTarget(node):
    return node['targets'][0]


def getValue(node):
    return node['value']


def isNameNode(node):
    return node['ast_type'] == "Name"

def isValueNode(node):
    return node['ast_type'] == "Num"


def isTainted(valueNode):
    if(vars.__contains__(valueNode['n'])):
        return True
    else:
        return False


def handleAssign(node):
    valueNode = getValue(node)
    if isValueNode(valueNode):
        if isTainted(valueNode):
            taintedVars.append(getTarget(node)['id'])
            return node
        else:
            vars.append(getTarget(node)['id'])
            return node
    else:
        # TODO
        return node


def handleCall(node):
    pass


def handleExpr(node):
    pass


def isSink():
    pass


def isSanitizer():
    pass


def isSource():
    pass


class MyNode:
    ast_operators = ['If', 'While', 'For']

    def __init__(self, ast_type, line):
        # TODO: Add more information if needed
        self.ast_type = ast_type
        self.line = line
        self.variable = None

    def __repr__(self):
        return "{0} - {1}".format(self.ast_type, self.line)

    @staticmethod
    def parse_instructions(json_instructions):
        nodes = list()

        for node in json_instructions:
            # Append the main instruction
            new_instruction = MyNode(node['ast_type'], node['lineno'])
            if (node['ast_type'] == 'Assign'):
                nodes.append(handleAssign(node))
            elif (node['ast_type'] == 'Call'):
                handleCall(node)
            elif (node['ast_type'] == 'Expr'):
                handleExpr(node)
            else:
                continue

        return nodes
