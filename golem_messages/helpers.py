import datetime
import math

from .constants import DEFAULT_UPLOAD_RATE, DOWNLOAD_LEADIN_TIME


def maximum_download_time(
        size: int, rate: int = DEFAULT_UPLOAD_RATE) -> datetime.timedelta:
    """
    the maximum time (expressed as a timedelta) allowed for upload/download
    of a resource of a given size between peers or between a Golem node and
    the Concent.

    :param size: size of payload in bytes
    :param rate: transfer rate in KB/s
    :return: the maxium
    """

    bytes_per_sec = rate << 10
    download_time = datetime.timedelta(
        seconds=int(math.ceil(size / bytes_per_sec))
    )

    return DOWNLOAD_LEADIN_TIME + download_time
