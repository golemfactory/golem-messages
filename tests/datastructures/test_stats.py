import unittest

from golem_messages.datastructures import stats
from golem_messages import exceptions


class TestProviderStats(unittest.TestCase):
    def setUp(self) -> None:
        self.stats_dict = {
            'cpu_stats': {
                'cpu_usage': {
                    'total_usage': 210742887,
                    'percpu_usage': [
                        2294161, 4289803, 2629870, 13575808, 153013241, 4415022,
                        5868137, 5475479, 3252549, 3329389, 7260411, 5347658
                    ],
                    'usage_in_kernelmode': 30000000,
                    'usage_in_usermode': 150000000
                },
                'throttling_data': {}
            },
            'memory_stats': {
                'usage': {
                    'usage': 4554752,
                    'max_usage': 7172096,
                    'failcnt': 0,
                    'limit': 9223372036854771712
                },
                'swap_usage': {},
                'kernel_usage': {
                    'usage': 2748416,
                    'max_usage': 2818048,
                    'failcnt': 0,
                    'limit': 9223372036854771712
                },
                'kernel_tcp_usage': {},
                'stats': {}
            },
            'pids_stats': {},
            'blkio_stats': {
                'io_merged_recursive': {
                    'major': 1500,
                    'minor': 0,
                    'op': 'test',
                    'value': 0
                },
                'sectors_recursive': {
                    'major': 666,
                    'minor': 0,
                    'op': 'test',
                    'value': 0
                }
            }
        }

    def test_deserialize(self):
        stats.ProviderStats(**self.stats_dict)

    def test_serialize(self):
        deserialized = stats.ProviderStats(**self.stats_dict)
        serialized = deserialized.to_dict()

        self.assertIsNone(serialized['pids_stats'])
        self.assertIsNone(serialized['cpu_stats']['throttling_data'])

    def test_repr(self):
        provider_stats = stats.ProviderStats(**self.stats_dict)
        self.assertEqual(repr(provider_stats),
                         '<ProviderStats: %r>' % provider_stats.to_dict())

    def test_validate_cpu_stats_invalid_type(self):
        self.stats_dict['cpu_stats'] = []

        with self.assertRaisesRegex(
            exceptions.FieldError,
            r"^Should be a dict or CpuStats \[cpu_stats:\[\]\]$"
        ):
            stats.ProviderStats(**self.stats_dict)

    def test_validate_memory_usage_invalid_type(self):
        self.stats_dict['memory_stats']['usage'] = 'I should be a dict'

        with self.assertRaisesRegex(
            exceptions.FieldError,
            r"^Should be a dict or MemoryData \[usage:'I should be a dict'\]"
        ):
            stats.ProviderStats(**self.stats_dict)
