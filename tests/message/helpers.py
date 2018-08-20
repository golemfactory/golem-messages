from golem_messages import shortcuts


def dump_and_load(msg):
    msg_d = shortcuts.dump(msg, None, None)
    return shortcuts.load(msg_d, None, None)
