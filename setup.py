#!/usr/bin/env python
# Copyright 2012 Hewlett-Packard Development Company, L.P. All Rights Reserved.
#
# Author: Simon McCartney <simon.mccartney@hp.com>
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

from setuptools import setup, find_packages

setup(
    name='python-xtrabackup2swift',
    version='0.0.5',
    description='xtrabackup wrappers to store & retrieve from swift',
    author='Simon McCartney',
    author_email='simon.mccartney@hp.com',
    url='https://github.com/moniker-dns/python-xtrabackup2swift',
    packages=find_packages(exclude=['bin']),
    install_requires=[
        'pycrypto',
        'python-swiftclient',
        'python-keystoneclient',
    ],
    scripts=[
        'bin/xtrabackup2swift',
        'bin/swift2xtrabackup'
    ],
    classifiers=[
        'Development Status :: 3 - Alpha',
        'License :: OSI Approved :: Apache Software License',
        'Operating System :: OS Independent',
        'Programming Language :: Python :: 2.6',
        'Programming Language :: Python :: 2.7',
        'Environment :: Console'
    ],
)
