import datetime
import time
import unittest

from golem_messages import cryptography
from golem_messages import idgenerator
from golem_messages import utils
from golem_messages import exceptions
from golem_messages.datastructures import tasks as dt_tasks
from golem_messages.factories.datastructures import tasks as dt_tasks_factories


class TestTaskHeader(unittest.TestCase):
    def setUp(self):
        self.key_id = b'key_id'
        self.th_dict_repr = {
            'mask': None,
            "task_id": idgenerator.generate_id(self.key_id),
            "task_owner": {
                "node_name": "Bob's node",
                "key": utils.encode_hex(self.key_id),
                "pub_addr": "10.10.10.10",
                "pub_port": 10101
            },
            "environment": "DEFAULT",
            "deadline": int(time.time() + 1201),
            "subtask_timeout": 120,
            "subtasks_count": 21,
            "max_price": 10,
            "min_version": "0.19.0",
            "resource_size": 0,
            "estimated_memory": 0,
        }

    def test_validate_ok(self):
        dt_tasks.TaskHeader(**self.th_dict_repr)

    def test_validate_illegal_deadline(self):
        self.th_dict_repr['deadline'] = datetime.datetime.now()
        with self.assertRaisesRegex(
            exceptions.FieldError,
            r"^Should be an integer \[deadline:datetime\.datetime\(.+\)\]$"
        ):
            dt_tasks.TaskHeader(**self.th_dict_repr)

    def test_validate_deadline_passed(self):
        self.th_dict_repr['deadline'] = int(time.time() - 10)
        with self.assertRaisesRegex(
            exceptions.FieldError,
            "Deadline already passed"
        ):
            dt_tasks.TaskHeader(**self.th_dict_repr)

    def test_validate_illegal_timeout(self):
        self.th_dict_repr['subtask_timeout'] = "abc"
        with self.assertRaisesRegex(
            exceptions.FieldError,
            r"Should be an integer \[subtask_timeout:'abc'\]"
        ):
            dt_tasks.TaskHeader(**self.th_dict_repr)

    def test_validate_negative_timeout(self):
        self.th_dict_repr['subtask_timeout'] = -131
        with self.assertRaisesRegex(
            exceptions.FieldError,
            "Subtask timeout is less than 0",
        ):
            dt_tasks.TaskHeader(**self.th_dict_repr)

    def test_validate_no_task_id(self):
        del self.th_dict_repr['task_id']
        with self.assertRaisesRegex(
            exceptions.FieldError,
            r'^Field required \[task_id:None\]$',
        ):
            dt_tasks.TaskHeader(**self.th_dict_repr)

    def test_validate_no_task_owner(self):
        del self.th_dict_repr['task_owner']
        with self.assertRaisesRegex(
            exceptions.FieldError,
            r"^Field required \[task_owner:None\]$",
        ):
            dt_tasks.TaskHeader(**self.th_dict_repr)

    def test_validate_no_subtasks_count(self):
        del self.th_dict_repr['subtasks_count']
        with self.assertRaisesRegex(
            exceptions.FieldError,
            r"^Field required \[subtasks_count:None\]$"
        ):
            dt_tasks.TaskHeader(**self.th_dict_repr)

    def test_validate_subtasks_count_invalid_type(self):
        self.th_dict_repr['subtasks_count'] = None
        with self.assertRaisesRegex(
            exceptions.FieldError,
            r"^Should be an integer \[subtasks_count:None\]$",
        ):
            dt_tasks.TaskHeader(**self.th_dict_repr)

    def test_validate_subtasks_count_too_low(self):
        self.th_dict_repr['subtasks_count'] = -1
        with self.assertRaisesRegex(
            exceptions.FieldError,
            r"^Subtasks count is less than 1 \[subtasks_count:-1\]$"
        ):
            dt_tasks.TaskHeader(**self.th_dict_repr)


class TestTaskHeaderSignature(unittest.TestCase):
    def setUp(self):
        self.task_header = dt_tasks_factories.TaskHeaderFactory()
        self.keys = cryptography.ECCx(None)

    def test_signature(self):
        self.assertIsNone(self.task_header.signature)
        self.task_header.sign(private_key=self.keys.raw_privkey)  # noqa pylint: disable=no-value-for-parameter
        self.assertIsInstance(self.task_header.signature, bytes)

    def test_verify_ok(self):
        self.task_header.sign(private_key=self.keys.raw_privkey)  # noqa pylint: disable=no-value-for-parameter
        self.task_header.verify(public_key=self.keys.raw_pubkey)

    def test_verify_fail(self):
        self.task_header.signature = 'sp00f'
        with self.assertRaises(exceptions.InvalidSignature):
            self.task_header.verify(public_key=self.keys.raw_pubkey)
