#!/bin/env python3

# Copyright (c) 2021 Seagate Technology LLC and/or its Affiliates
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published
# by the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU Affero General Public License for more details.
# You should have received a copy of the GNU Affero General Public License
# along with this program. If not, see <https://www.gnu.org/licenses/>.
# For any questions about this software or licensing,
# please email opensource@seagate.com or cortx-questions@seagate.com.

import os
import glob
from setuptools import setup, find_packages
import json
import sys
from fnmatch import fnmatch

if not os.path.isfile("./rgw.conf.sample"):
    files = [f for f in os.listdir('.') if os.path.isfile(f)]
    for f in files:
        print(f)
    print("error: rgw.conf.sample file not found!!", file=sys.stderr)
    sys.exit(1)

with open("rgw.conf.sample") as conf_file:
    build_data = json.load(conf_file)

# Fetch install_path
install_path = build_data["install_path"]
# e.g mgw path will be /opt/seagate/cortx/rgw
rgw_path = "%s/rgw" % install_path

if not os.path.isfile("./VERSION"):
    print("error: VERSION file not found!", file=sys.stderr)
    sys.exit(1)

# Fetch version
with open("VERSION") as v_file:
    rgw_version = v_file.read().strip()

# Get the list of template files
tmpl_files = glob.glob('src/setup/templates/*.*')

#with open('LICENSE', 'r') as lf:
#     license = lf.read()

with open('README.md', 'r') as rf:
    long_description = rf.read()

# Get list of mini-provisioner classes
mini_prov_files = glob.glob('src/setup/*.py')

def get_install_requirements() -> list:
    with open('python_requirements.txt') as req:
        install_requires = [line.strip() for line in req]
    return install_requires

def get_requirements_files() -> list:
    req_file_list = [req_file for req_file in os.listdir(".") \
        if fnmatch(req_file, "python_requirements.*txt")]
    return req_file_list

setup(name='cortx-rgw',
      version=rgw_version,
      url='https://github.com/Seagate/cortx-rgw-integration',
      license='Seagate',
      description='RGW integration code for CORTX',
      package_dir={'cortx': 'src'},
      packages=find_packages(),
      package_data={
        'cortx': ['py.typed'],
        'cortx.src.setup': ['*.py'],
      },
      long_description=long_description,
      zip_safe=False,
      python_requires='>=3.6',
      entry_points={
          'console_scripts': [
              'rgw_setup = cortx.rgw.setup.rgw_setup:main',
              ]
      },
      data_files =[ ('%s/templates' % rgw_path, tmpl_files),
                    ('%s/conf' % rgw_path, ['rgw.conf.sample']),
                    ('%s/mini-provisioner' % rgw_path, mini_prov_files),
                  ],
      install_requires=get_install_requirements())

