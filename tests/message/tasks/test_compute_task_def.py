# pylint:disable=no-self-use
import unittest
import unittest.mock as mock

from golem_messages import factories
from golem_messages import message


class ComputeTaskDefTestCase(unittest.TestCase):
    @mock.patch('golem_messages.message.tasks.ComputeTaskDef.validate_task_id')
    def test_task_id_validator(self, v_mock):
        ctd = factories.tasks.ComputeTaskDefFactory()
        v_mock.assert_called_once_with(
            value=ctd['task_id'],
        )

    @mock.patch(
        'golem_messages.message.tasks.ComputeTaskDef.validate_subtask_id',
    )
    def test_subtask_id_validator(self, v_mock):
        ctd = factories.tasks.ComputeTaskDefFactory()
        v_mock.assert_called_once_with(
            value=ctd['subtask_id'],
        )

    def test_type(self):
        ctd = message.ComputeTaskDef()
        msg = factories.tasks.TaskToComputeFactory(compute_task_def=ctd)
        s = msg.serialize()
        msg2 = message.Message.deserialize(s, None)
        self.assertEqual(ctd, msg2.compute_task_def)
        self.assertIsInstance(msg2.compute_task_def, message.ComputeTaskDef)

    def test_extra_data(self):
        ctd = factories.tasks.ComputeTaskDefFactory()
        extra_data = ctd['extra_data']
        self.assertIsInstance(extra_data, dict)
        self.assertEqual(extra_data['path_root'], '')
        self.assertTrue(extra_data['start_task'])
        self.assertTrue(extra_data['end_task'])
        self.assertTrue(extra_data['total_tasks'])
        self.assertTrue(extra_data['outfilebasename'])
        self.assertTrue(extra_data['scene_file'])
        self.assertTrue(extra_data['script_src'])
        self.assertTrue(extra_data['frames'])
        self.assertTrue(extra_data['output_format'])
