import datetime
import math

from golem_messages import constants


def subtask_verification_time(report_computed_task) -> datetime.timedelta:
    """Returns time allowed for requestor to Ack/Reject results from provider.
    """
    mdt = maximum_download_time(
        size=report_computed_task.size,
    )
    ttc_dt = datetime.datetime.utcfromtimestamp(
        report_computed_task.task_to_compute.timestamp,
    )
    subtask_dt = datetime.datetime.utcfromtimestamp(
        report_computed_task.task_to_compute.compute_task_def['deadline'],
    )
    subtask_timeout = subtask_dt - ttc_dt
    return (4 * constants.CMT) + (3 * mdt) + (0.5 * subtask_timeout)


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


def requestor_deposit_amount(total_task_price: int) -> (int, int):
    """Returns required_amount, suggested_amount"""
    return total_task_price*2, total_task_price*4


def provider_deposit_amount(subtask_price: int) -> (int, int):
    """Returns required_amount, suggested_amount"""
    return subtask_price, 4*subtask_price
