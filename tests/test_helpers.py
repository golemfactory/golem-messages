from datetime import timedelta
from unittest import TestCase

from golem_messages.constants import DEFAULT_UPLOAD_RATE, DOWNLOAD_LEADIN_TIME
from golem_messages.helpers import maximum_download_time


class MaximumDownloadTimeTest(TestCase):
    def test_maximum_download_time(self):
        secs = 100
        size = secs * (DEFAULT_UPLOAD_RATE << 10)
        expected = timedelta(seconds=secs) + DOWNLOAD_LEADIN_TIME
        self.assertEqual(expected, maximum_download_time(size))

    def test_maximum_download_time_w_rate(self):
        size = 10240 << 10  # 10M
        rate = 1024  # KB/s
        expected = timedelta(seconds=10) + DOWNLOAD_LEADIN_TIME
        self.assertEqual(expected, maximum_download_time(size, rate))
