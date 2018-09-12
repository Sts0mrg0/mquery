from pyparsing import *
import re
import itertools
import string


class YaraParser(object):
    def __init__(self, parsed_yara):
        self.strings = parsed_yara['strings']
        self.condition = ' '.join(parsed_yara['condition_terms'])

    def get_string_names(self):
        return [s['name'] for s in self.strings]

    def string_to_query(self, value):
        value = value.strip()
        if value[0] == '{' and value[-1] == '}':
            hexbytes = ['']

            # make a list of characters without first and last one ("{" and "}")
            chars = list(value[:-1][1:])

            while chars:
                hexdigs = 'ABCDEF0123456789?'
                char = chars.pop(0).upper()

                if char == '[':
                    while chars and chars.pop(0) != ']':
                        pass

                    if hexbytes[-1]:
                        hexbytes.append('')

                    continue

                if char == ' ':
                    continue

                if char not in hexdigs:
                    assert False

                char2 = chars.pop(0)

                if char2 not in hexdigs:
                    assert False

                hexbyte = char + char2

                if hexbyte == '??':
                    if hexbytes[-1]:
                        hexbytes.append('')
                else:
                    hexbytes[-1] += hexbyte

            hexbytes = list(filter(lambda hexbyte: hexbyte >= 6, hexbytes))

            if not hexbytes:
                hexbytes = ['']

            return '(' + ' & '.join('{' + hexbyte + '}' for hexbyte in hexbytes) + ')'
        elif value[0] == '"' and value[-1] == '"':
            return "\"" + value[1:-1] + "\""
        elif value[0] == "\"" and value[-1] == "\"":
            return value
        else:
            assert False

    def act_expression(self, a, d, am):
        if len(am) == 3:
            op = am[1]

            if op == 'and':
                op = '&'
            elif op == 'or':
                op = '|'

            return '({} {} {})'.format(am[0], op, am[2])
        return am

    def act_multiselector(self, a, d, am):
        if am[0] == 'any':
            return '(' + ' | '.join(am[2]) + ')'
        elif am[0] == 'all':
            return '(' + ' & '.join(am[2]) + ')'
        elif am[0].isdigit():
            return '(' + ' | '.join(
                '(' + ' & '.join(opt) + ')' for opt in itertools.combinations(am[2], int(am[0]))) + ')'
        else:
            raise Exception('what')

    def act_list(self, a, d, am):
        l = am[0]
        out = []
        for i in range(len(l)):
            reg = re.escape(l[i])
            reg = reg.replace('\\*', '.*')
            for s in self.get_string_names():
                if re.search(reg, s):
                    out.append(s)
        return [out]

    def act_them(self, a, d, am):
        return [self.get_string_names()]

    def act_ignore(self, a, d, am):
        return []

    def act_variable(self, a, d, am):
        if not am[0].startswith('$'):
            return "()"

    def get_grammar(self):
        atom = Forward()
        expression = Forward()

        variable = Word(string.ascii_lowercase + string.ascii_uppercase + string.digits + "[]._#*$").setParseAction(
            self.act_variable)
        variable_list = Or([
            Literal('(').suppress()
            + Group(variable + ZeroOrMore(Literal(',').suppress() + variable)).setParseAction(self.act_list)
            + Literal(")").suppress(),
            Literal('them').setParseAction(self.act_them)
        ])
        count_specifier = Or([
            Literal('any'),
            Literal('all'),
            Word('0123456789'),
        ])

        bracketed_atom = (Literal('(').suppress() + expression + Literal(')').suppress())

        offset_var = Word(string.ascii_letters + string.digits).setParseAction(self.act_ignore)
        offset_expr = (offset_var + Literal('(').suppress() + offset_var + Literal(')').suppress() + '==' + Word(
            string.hexdigits + 'x')).setParseAction(self.act_ignore)

        comparison_var = Word("<>").setParseAction(self.act_ignore)
        comparison_expr = (variable + comparison_var + variable).setParseAction(self.act_ignore)
        ignoreme_expr = (variable + '==' + Word(string.digits)).setParseAction(self.act_ignore)

        atom << Or([
            offset_expr,
            variable,
            ignoreme_expr,
            comparison_expr,
            bracketed_atom,
            (count_specifier + 'of' + variable_list).setParseAction(self.act_multiselector),
        ])

        expression << (atom + Optional(
            Or([
                'and' + expression,
                'or' + expression,
            ]),
        )).setParseAction(self.act_expression)

        return expression + Literal(';').suppress()

    def pre_parse(self):
        grammar = self.get_grammar()
        result = grammar.parseString(self.condition + ';')
        return result.asList()[0]

    def replace_strings(self, cond):
        for string in self.strings:
            name = '(?<=[() ])' + re.escape(string['name']) + '(?=[() ])'

            value = string['value']

            str_q = self.string_to_query(value)

            if 'modifiers' in string and 'wide' in string['modifiers']:
                str_q = 'w' + str_q

            cond = re.sub(name, str_q, cond)
            cond = cond.replace('()', '""')  # "always true"

        return cond

    def parse(self):
        pre_parsed = self.pre_parse()
        return self.replace_strings(pre_parsed)
