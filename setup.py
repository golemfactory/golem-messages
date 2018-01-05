#!/usr/bin/env python3

import pathlib

from setuptools import setup
try:
    from version import get_version
except ImportError:
    def get_version(cwd, **kwargs):
        p = pathlib.Path(cwd) / 'RELEASE-VERSION'
        with p.open('r') as f:
            return f.read()

version_cwd = str(pathlib.Path(__file__).parent / 'golem_messages')

# ./setup.py bdist_egg


setup(
    name='Golem-Messages',
    version=get_version(prefix='v', cwd=version_cwd),
    url='https://github.com/golemfactory/golem-messages',
    maintainer='The Golem team',
    maintainer_email='tech@golem.network',
    packages=['golem_messages'],
    package_data={
        'golem_messages': [
            'RELEASE-VERSION',
        ],
    },
    python_requires='>=3.5',
    install_requires=[
        'bitcoin',
        'cbor2==3.0.4',
        'coincurve>=5.0.1',
        'ethereum==1.6.1',
        'pyelliptic==1.5.7',
        'pytz',
    ],
    tests_require=[
        'pycodestyle',
        'freezegun',
    ],
)
