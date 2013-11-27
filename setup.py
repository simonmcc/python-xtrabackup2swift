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
import textwrap
from setuptools import setup, find_packages
from xtrabackup2swift.openstack.common import setup as common_setup

install_requires = common_setup.parse_requirements(['tools/pip-requires'])
tests_require = common_setup.parse_requirements(['tools/test-requires'])
setup_require = common_setup.parse_requirements(['tools/setup-requires'])
dependency_links = common_setup.parse_dependency_links([
    'tools/pip-requires',
    'tools/test-requires',
    'tools/setup-requires'
])

setup(
    name='python-xtrabackup2swift',
    version=common_setup.get_version('python-xtrabackup2swift'),
    description='Manage a shelf full of git repos',
    author='Simon McCartney',
    author_email='simon.mccartney@hp.com',
    url='https://github.com/moniker-dns/python-xtrabackup2swift',
    packages=find_packages(exclude=['bin']),
    include_package_data=True,
    test_suite='nose.collector',
    setup_requires=setup_require,
    install_requires=install_requires,
    tests_require=tests_require,
    extras_require={'test': tests_require},
    dependency_links=dependency_links,
    scripts=[
        'bin/xtrabackup2swift',
        'bin/xtrabackup2swift',
    ],
    cmdclass=common_setup.get_cmdclass(),
    entry_points=textwrap.dedent("""
        [xtrabackup2swift.cli]
        install = xtrabackup2swift.cli.install:GitShelfInstallCommand
        status = xtrabackup2swift.cli.status:GitShelfStatusCommand
        """),
    classifiers=[
        'Development Status :: 3 - Alpha',
        'License :: OSI Approved :: Apache Software License',
        'Operating System :: OS Independent',
        'Programming Language :: Python :: 2.6',
        'Programming Language :: Python :: 2.7',
        'Environment :: Console',
    ],
)
