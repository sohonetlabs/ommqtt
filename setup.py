#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
from setuptools import setup, find_packages
from distutils.util import convert_path

root_dir = os.path.abspath(os.path.dirname(__file__))

with open(os.path.join(root_dir,'README.md')) as readme_file:
    readme = readme_file.read()

requirements = [
    'paho-mqtt',
]

test_requirements = [
    'pytest',
    'pytest-cov',
    'pytest-mock',
    'pytest-pythonpath',
]

setup(
    name='cvp_ommqtt',
    version="0.2.1",
    description="OMMQTT output module for rsyslog using MQTT",
    long_description=readme + '\n',
    author="Sohonet",
    author_email='dev@sohonet.com',
    url='https://github.com/sohonetlabs/ommqtt',
    entry_points={
        'console_scripts': [
            'cvp-ommqtt=ommqtt.ommqtt:main'
        ]
    },
    packages=find_packages(exclude=['tests', 'tests.*']),
    package_dir={'ommqtt': 'ommqtt'},
    install_requires=requirements,
    license="MIT license",
    zip_safe=False,
    keywords='cvp_ommqtt',
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Natural Language :: English',
        'Programming Language :: Python :: 3.8',
    ],
    test_suite='tests',
    tests_require=test_requirements
)