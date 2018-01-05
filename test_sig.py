#!/usr/bin/env python3.5

import sys

import golem_messages
from golem_messages import cryptography
from golem_messages import message

CONCENT_PUBLIC_KEY  = b'\xf3\x97\x19\xcdX\xda\x86tiP\x1c&\xd39M\x9e\xa4\xddb\x89\xb5,]O\xd5cR\x84\xb85\xed\xc9\xa17e,\xb2s\xeb\n1\xcaN.l\xba\xc3\xb7\xc2\xba\xff\xabN\xde\xb3\x0b\xa6l\xbf6o\x81\xe0;'
CONCENT_PRIVATE_KEY = b'l\xcdh\x19\xeb$>\xbcG\xa1\xc7v\xe8\xd7o\x0c\xbf\x0e\x0fM\x89lw\x1e\xd7K\xd6Hnv$\xa2'

def main():
    message_timestamp = 1546171200
    msg = message.TaskToCompute(timestamp=message_timestamp)
    msg.compute_task_def = message.ComputeTaskDef({
        'deadline': message_timestamp + 3600,
        'task_id': 'http://storage.concent.golem.network/',
        'subtask_id': b'\xf3\x97\x19\xcdX\xda\x86tiP\x1c&\xd39M\x9e\xa4\xddb\x89\xb5,]O\xd5cR\x84\xb85\xed\xc9\xa17e,\xb2s\xeb\n1\xcaN.l\xba\xc3\xb7\xc2\xba\xff\xabN\xde\xb3\x0b\xa6l\xbf6o\x81\xe0;',
        'extra_data': {
            'path': 'blender/benchmark/test_task/scene-Helicopter-27-cycles.blend',
            'checksum': '098f6bcd4621d373cade4e832627b4f6',
            'size': 1024,
        },
        'short_description': 'download',
    })
    serialized = golem_messages.dump(msg, CONCENT_PRIVATE_KEY, CONCENT_PUBLIC_KEY)
    load_msg = golem_messages.load(serialized, CONCENT_PRIVATE_KEY, CONCENT_PUBLIC_KEY, check_time=False)
    assert load_msg is not None
    # Try verifying without cached payload
    cryptography.ecdsa_verify(CONCENT_PUBLIC_KEY, msg.sig, msg.get_short_hash())

if __name__ == '__main__':
    for x in range(10**5):
        sys.stdout.write('.')
        if (x % 80) == 0:
            sys.stdout.write('{}\n'.format(x))
        main()

