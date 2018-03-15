import datetime
import math

from golem_messages import constants


def maximum_results_patience(task_to_compute) -> datetime.timedelta:
    """Returns time allowed for requestor to Ack/Reject results from provider.
    """
    now = datetime.datetime.utcnow()
    deadline = datetime.datetime.utcfromtimestamp(
        task_to_compute.compute_task_def['deadline'],
    )
    deadline_delay = now - deadline
    final_delay = datetime.timedelta(
        seconds=constants.SUBTASK_VERIFICATION_TIME,
    ) + deadline_delay
    return final_delay


def maximum_download_time(
        size: int,
        rate: int = constants.DEFAULT_UPLOAD_RATE) -> datetime.timedelta:
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

    return constants.DOWNLOAD_LEADIN_TIME + download_time
