import pathlib

from .cryptography import ECCx
from .shortcuts import dump, load, profiler

# PEP-396
with (pathlib.Path(__file__).parent / 'RELEASE-VERSION').open('r') as f:
    __version__ = f.read()
