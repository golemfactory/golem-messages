#!/usr/bin/env python3

from setuptools import setup
import unittest

# ./setup.py bdist_egg


setup(
    name='Golem Messages',
    version='1.1.2',
    url='https://github.com/golemfactory/golem-messages',
    packages=['golem_messages'],
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
