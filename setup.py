#!/usr/bin/env python3

from setuptools import setup
import unittest

# ./setup.py bdist_egg


def test_suite():
    test_loader = unittest.TestLoader()
    test_suite = test_loader.discover('tests', pattern='test_*.py')
    return test_suite


setup(
    name='Golem Messages',
    version='1.0.0',
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
    test_suite='setup.test_suite',
    extras_require={
        'test': ['pycodestyle', 'freezegun'],
    },
)
