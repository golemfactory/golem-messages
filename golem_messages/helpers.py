import datetime
import math

from golem_messages import constants


def maximum_results_patience(report_computed_task) -> datetime.timedelta:
    """Returns time allowed for requestor to Ack/Reject results from provider.
    """
    now = datetime.datetime.utcnow()
    deadline = datetime.datetime.utcfromtimestamp(
        report_computed_task.task_to_compute.compute_task_def['deadline'],
    )
    deadline_delay = now - deadline
    subtask_verification_time = 4 * constants.DEFAULT_MSG_LIFETIME
    subtask_verification_time += 3 * maximum_download_time(
        size=report_computed_task.size
    )
    final_delay = subtask_verification_time + deadline_delay
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
