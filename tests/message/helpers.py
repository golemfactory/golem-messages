from golem_messages import datastructures
from golem_messages import shortcuts


def dump_and_load(msg):
    msg_d = shortcuts.dump(msg, None, None)
    return shortcuts.load(msg_d, None, None)


def nested(msg):
    return datastructures.NestedMessage(msg.header, msg.sig, msg.slots())


def single_nested(msg):
    return False, nested(msg)


def list_nested(l):
    return True, [nested(msg) for msg in l]
