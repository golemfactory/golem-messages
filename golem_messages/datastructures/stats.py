import functools
from typing import Optional

from golem_messages import datastructures
from golem_messages import validators


class BlockIoEntry(datastructures.FrozenDict):

    ITEMS = {
        'major': 0,
        'minor': 0,
        'op': None,
        'value': 0,
    }


validate_block_stat_entry = functools.partial(
    validators.fail_unless,
    check=lambda x: isinstance(x, (dict, BlockIoEntry)),
    fail_msg="Should be a dict or BlockIoEntry",
)


class BlockIoStats(datastructures.Container):
    """ These stats refer to the number of bytes transferred to and from the
        block device. """

    slot_names = ['io_merged_recursive', 'io_queue_recursive',
                  'io_service_bytes_recursive', 'io_service_time_recursive',
                  'io_serviced_recursive', 'io_time_recursive',
                  'io_wait_time_recursive', 'sectors_recursive']

    __slots__ = {slot: (validate_block_stat_entry, ) for slot in slot_names}


class CpuUsage(datastructures.FrozenDict):
    """ Stats on the total CPU usage for the subtask. All values are in
        nanoseconds. """

    ITEMS = {
        'percpu_usage': [],
        'total_usage': 0,
        'usage_in_kernelmode': 0,
        'usage_in_usermode': 0,
    }


class ThrottlingData(datastructures.FrozenDict):

    ITEMS = {
        # Number of periods with throttling active
        'periods': 0,
        # Number of periods with throttling limit reached
        'throttled_periods': 0,
        # Total time when throttling was active (in nanoseconds)
        'throttled_time': 0
    }


class CpuStats(datastructures.Container):
    """ Aggregate CPU statistics for a given subtask. Both fields are
        considered optional. """

    __slots__ = {
        'cpu_usage': (
            validators.validate_dict,
        ),
        'throttling_data': (
            validators.validate_dict,
        ),
    }

    @classmethod
    def deserialize_cpu_usage(cls, value: dict) -> Optional[CpuUsage]:
        return CpuUsage(**value) if value else None

    @classmethod
    def deserialize_throttling_data(cls, value: dict) \
            -> Optional[ThrottlingData]:
        return ThrottlingData(**value) if value else None

    @classmethod
    def serialize_cpu_usage(cls, value: CpuUsage) -> Optional[CpuUsage]:
        return value if value else None

    @classmethod
    def serialize_throttling_data(cls, value: ThrottlingData) \
            -> Optional[ThrottlingData]:
        return value if value else None


class MemoryData(datastructures.FrozenDict):

    ITEMS = {
        'failcnt': 0,
        'limit': 0,
        'max_usage': 0,
        'usage': 0,
    }


validate_memory_data = functools.partial(
    validators.fail_unless,
    check=lambda x: isinstance(x, (dict, MemoryData)),
    fail_msg="Should be a dict or MemoryData",
)


class MemoryStats(datastructures.Container):

    memory_data_slots = ['kernel_tcp_usage', 'kernel_usage', 'swap_usage',
                         'usage']

    __slots__ = {slot: (validate_memory_data, ) for slot in memory_data_slots}

    __slots__.update({
        'cache': (
            validators.validate_integer,
        ),
        'stats': (
            validators.validate_dict,
        ),
        'use_hierarchy': (
            validators.validate_boolean,
        ),
    })


class PidStats(datastructures.Container):

    __slots__ = {
        'current': (
            validators.validate_integer,
        ),
        'limit': (
            validators.validate_integer,
        )
    }


class ProviderStats(datastructures.Container):
    """ Container for statistics on resource usage gathered on the provider's
        side. These are part of the ReportComputedTask message. All fields are
        considered optional (validators are there to indicate types and in case
        we wanted to make some of the fields required in the future). Generally,
        at least the CPU stats should be available in most cases. """

    __slots__ = {
        'blkio_stats': (
            functools.partial(
                validators.fail_unless,
                check=lambda x: isinstance(x, (dict, BlockIoStats)),
                fail_msg="Should be a dict or BlockIoStats",
            ),
        ),
        'cpu_stats': (
            functools.partial(
                validators.fail_unless,
                check=lambda x: isinstance(x, (dict, CpuStats)),
                fail_msg="Should be a dict or CpuStats",
            ),
        ),
        'memory_stats': (
            functools.partial(
                validators.fail_unless,
                check=lambda x: isinstance(x, (dict, MemoryStats)),
                fail_msg="Should be a dict or MemoryStats",
            ),
        ),
        'pids_stats': (
            functools.partial(
                validators.fail_unless,
                check=lambda x: isinstance(x, (dict, PidStats)),
                fail_msg="Should be a dict or PidStats",
            ),
        ),
    }

    @classmethod
    def deserialize_blkio_stats(cls, value: dict) -> Optional[BlockIoStats]:
        return BlockIoStats(**value) if value else None

    @classmethod
    def deserialize_cpu_stats(cls, value: dict) -> Optional[CpuStats]:
        return CpuStats(**value) if value else None

    @classmethod
    def deserialize_memory_stats(cls, value: dict) -> Optional[MemoryStats]:
        return MemoryStats(**value) if value else None

    @classmethod
    def deserialize_pids_stats(cls, value: dict) -> Optional[PidStats]:
        return PidStats(**value) if value else None

    @classmethod
    def serialize_blkio_stats(cls, value: BlockIoStats) -> Optional[dict]:
        return value.to_dict() if value else None

    @classmethod
    def serialize_cpu_stats(cls, value: CpuStats) -> Optional[dict]:
        return value.to_dict() if value else None

    @classmethod
    def serialize_memory_stats(cls, value: MemoryStats) -> Optional[dict]:
        return value.to_dict() if value else None

    @classmethod
    def serialize_pids_stats(cls, value: PidStats) -> Optional[dict]:
        return value.to_dict() if value else None
