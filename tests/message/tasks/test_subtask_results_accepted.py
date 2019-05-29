import calendar
import time
import unittest

from golem_messages import exceptions
from golem_messages import factories
from golem_messages import message
from golem_messages import shortcuts
from golem_messages.factories.helpers import override_timestamp

from tests.message import mixins, helpers


class SubtaskResultsAcceptedTest(mixins.RegisteredMessageTestMixin,
                                 mixins.SerializationMixin,
                                 mixins.TaskIdMixin,
                                 unittest.TestCase):
    FACTORY = factories.tasks.SubtaskResultsAcceptedFactory
    MSG_CLASS = message.tasks.SubtaskResultsAccepted
    TASK_ID_PROVIDER = 'report_computed_task'

    def test_factory(self):
        self.assertIsInstance(self.msg, message.tasks.SubtaskResultsAccepted)

    def test_report_computed_task_wrong_class(self):
        with self.assertRaises(exceptions.FieldError):
            message.tasks.SubtaskResultsAccepted(slots=(
                ('report_computed_task', 'something else'),
            ))

    def test_report_computed_task_correct(self):
        msg = message.tasks.SubtaskResultsAccepted(slots=(
            (
                'report_computed_task',
                helpers.single_nested(
                    factories.tasks.ReportComputedTaskFactory(),
                ),
            ),
        ))
        self.assertIsInstance(
            msg.report_computed_task,
            message.tasks.ReportComputedTask,
        )

    def test_payment_ts_in_future_validation_raises(self):
        serialized_sra = self._get_serialized_sra(payment_ts_offset=1)
        with self.assertRaises(exceptions.ValidationError):
            shortcuts.load(serialized_sra, None, None)

    def test_payment_ts_in_past_validation_raises(self):
        serialized_sra = self._get_serialized_sra(payment_ts_offset=-901)
        with self.assertRaises(exceptions.ValidationError):
            shortcuts.load(serialized_sra, None, None)

    def test_payment_ts_validation_ok(self):
        serialized_sra = self._get_serialized_sra()
        try:
            shortcuts.load(serialized_sra, None, None)
        except Exception:   # pylint: disable=broad-except
            self.fail("Should pass validation, but didn't")

    def _get_serialized_sra(self, payment_ts_offset=0):
        timestamp = calendar.timegm(time.gmtime())
        payment_ts = timestamp + payment_ts_offset
        sra = self.FACTORY(payment_ts=payment_ts)
        override_timestamp(sra, timestamp)
        return shortcuts.dump(sra, None, None)
