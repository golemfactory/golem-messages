import datetime
from unittest import TestCase
import unittest.mock as mock

from golem_messages import helpers
from golem_messages.constants import DEFAULT_UPLOAD_RATE, DOWNLOAD_LEADIN_TIME
from golem_messages import factories


class MaximumDownloadTimeTest(TestCase):
    def test_maximum_download_time(self):
        secs = 100
        size = secs * (DEFAULT_UPLOAD_RATE << 10)
        expected = datetime.timedelta(seconds=secs) + DOWNLOAD_LEADIN_TIME
        self.assertEqual(expected, helpers.maximum_download_time(size))

    def test_maximum_download_time_w_rate(self):
        size = 10240 << 10  # 10M
        rate = 1024  # KB/s
        expected = datetime.timedelta(seconds=10) + DOWNLOAD_LEADIN_TIME
        self.assertEqual(expected, helpers.maximum_download_time(size, rate))


class SubtaskVerificationTimeTestCase(TestCase):
    def setUp(self):
        self.msg = factories.tasks.ReportComputedTaskFactory(
            task_to_compute__compute_task_def__deadline=200,
        )
        factories.helpers.override_timestamp(self.msg.task_to_compute, 0)

    @mock.patch(
        "golem_messages.helpers.maximum_download_time",
        return_value=datetime.timedelta(seconds=10),
    )
    def test_svt(self, mdt_mock):
        result = helpers.subtask_verification_time(self.msg)
        mdt_mock.assert_called_once_with(size=self.msg.size)
        self.assertEqual(result, datetime.timedelta(seconds=14530))
