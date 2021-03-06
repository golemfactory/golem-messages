#!/usr/bin/env python3

import pathlib

from setuptools import setup
try:
    from version import get_version
except ImportError:
    def get_version(cwd, **_kwargs):
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
    packages=[
        'golem_messages',
        'golem_messages.datastructures',
        'golem_messages.message',
        'golem_messages.factories',
        'golem_messages.factories.datastructures',
    ],
    package_data={
        'golem_messages': [
            'RELEASE-VERSION',
        ],
    },
    python_requires='>=3.6',
    install_requires=[
        'bitcoin',
        'cbor==1.0.0',
        'coincurve>=7.1.0',
        'eth-account==0.2.3',
        'eth-keys==0.2.0b3',
        'eth-utils==1.0.3',
        'ethereum==1.6.1',
        'pyelliptic==1.5.10',
        'pytz',
        'rlp==0.6.0',
        'semantic_version',
    ],
    tests_require=[
        'Faker==0.8.9',
        'factory-boy==2.9.2',
        'pycodestyle==2.4.0',
        'pylint==1.9.2',
        'freezegun',
    ],
)
