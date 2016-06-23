# Copyright 2013 Li Cheng <licheng at microsoft com>
# Copyright 2016 Sheng Wang <kikyouer at gmail com>
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from ookm.lang.action import Action
from ookm.lang.node import Node
from ookm.lang.rule import Rule


class Predicate(Node):
    def __init__(self, name='Pred', lhs=None, rhs=None):
        super(Predicate, self).__init__(name)

        self.rule = None
        self.left_operand = lhs
        self.right_operand = rhs

    def __and__(self, rhs):
        Predicate._validate_rhs(rhs, Predicate, '&')
        return AndExpression(lhs=self, rhs=rhs)

    '''
    def __or__(self, rhs):
        Predicate._validate_rhs(rhs, Predicate, '|')
        return OrExpression(lhs=self, rhs=rhs)
    '''

    def __invert__(self):
        raise RuntimeError("Forbidden usage of invert on non-atomic predicate")

    def __rshift__(self, rhs):
        Predicate._validate_rhs(rhs, list, '>>')
        Predicate._validate_actions(rhs)
        return Rule(pred=[self], acts=rhs)

    def test(self, obj):
        return False

    def debug_print(self, indent=0):
        Predicate._print_indent(self.name, indent)
        self._debug_print_left_operand(indent)
        self._debug_print_right_operand(indent)

    def _debug_print_left_operand(self, indent):
        if self.left_operand:
            self.left_operand.debug_print(indent + 1)

    def _debug_print_right_operand(self, indent):
        if self.right_operand:
            self.right_operand.debug_print(indent + 1)

    @classmethod
    def _validate_rhs(cls, rhs, tp, op):
        if not isinstance(rhs, tp):
            raise Exception('Not \'%s\' after \'%s\'' % (tp.__name__, op))

    @classmethod
    def _validate_actions(cls, acts):
        for a in acts:
            if not isinstance(a, Action):
                raise Exception('Not \'Action\' in \'list\'')


class AtomicPredicate(Predicate):
    def __init__(self, name='APred'):
        super(AtomicPredicate, self).__init__(name, None, None)
        self.inverted = False
        self.fields_filter = {}
        self.matched_fields = {}

    def __invert__(self):
        self.inverted = True
        return self

    def __eq__(self, other):
        return super(AtomicPredicate, self).__eq__(other) and self.inverted == other.inverted

    def conflicts_with(self, other):
        return self.inverted != other.inverted

    def test(self, event):
        if self.inverted:
            return not self._test(event)
        else:
            return self._test(event)

    # default event test when the predicate is not negated
    def _test(self, event):
        pass


class AndExpression(Predicate):
    def __init__(self, name='And', lhs=None, rhs=None):
        super(AndExpression, self).__init__(name, lhs, rhs)

    def __rshift__(self, rhs):
        Predicate._validate_rhs(rhs, list, '>>')
        Predicate._validate_actions(rhs)
        return Rule(pred=AndExpression.build_sorted_predicates(self), acts=rhs)

    def test(self, obj):
        # If either lhs or rhs is None, operator & returns False.
        if not self.left_operand or not self.right_operand:
            return False
        else:
            return self.left_operand.test(obj) and self.right_operand.test(obj)

    @staticmethod
    def build_sorted_predicates(pred):
        return sorted(AndExpression._build_predicate_list(pred), key=lambda p: p.identifier())

    @staticmethod
    def _build_predicate_list(pred):
        if isinstance(pred, AtomicPredicate):
            return [pred]
        elif isinstance(pred, AndExpression):
            return [pred.right_operand] + AndExpression._build_predicate_list(pred.left_operand)
        else:
            return []


# WE DO NOT SUPPORT OrExpression! FOR NOW!
'''
class OrExpression(Predicate):
    def __init__(self, name='Or', lhs=None, rhs=None):
        super(OrExpression, self).__init__(name, lhs, rhs)

    def test(self, obj):
        # If either lhs or rhs is None, operator | returns False.
        if not self.left_operand or not self.right_operand:
            return False
        else:
            return self.left_operand.test(obj) or self.right_operand.test(obj)
'''


def predicates_intersects(l1, l2):
    # sanity check
    if not l1 or not l2:
        raise RuntimeError("l1 or l2 is empty!")

    d_lst = sorted(l1 + l2, key=lambda x: x.identifier())
    last = None
    for p in d_lst:
        if not last:
            last = p
            continue
        if last.identifier() != p.identifier():
            # e.g. A(4) and B
            last = p
        elif last.conflicts_with(p):
            return False
    return True


# standard conflict checking logic for single parameter predicate
def predicate_conflict_helper(obj1, x1, obj2, x2):
    inv1 = obj1.inverted
    inv2 = obj2.inverted
    if inv1 and inv2:
        return False
    elif inv1 != inv2:
        return x1 == x2
    else:
        return x1 != x2
