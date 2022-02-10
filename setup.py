#!/bin/env python3

# Copyright (c) 2022 Seagate Technology LLC and/or its Affiliates
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
import sys

RGW_INSTALL_PATH="/opt/seagate/cortx/rgw"

if not os.path.isfile("./VERSION"):
    print("error: VERSION file not found!!", file=sys.stderr)
    sys.exit(1)

# Get version info.
with open("VERSION") as v_file:
    rgw_intg_version = v_file.read().strip()

# Get rpm description.
with open('README.md', 'r') as rf:
    long_description = rf.read()

# Get list of mini-provisioner classes
mini_prov_files = glob.glob('./src/setup/*.py')

setup(name='cortx-rgw-integration',
      version=rgw_intg_version,
      url='https://github.com/Seagate/cortx-rgw-integration',
      license='Seagate',
      description='RGW integration code for CORTX',
      package_dir={'cortx': 'src'},
      packages=find_packages(),
      package_data={
        'cortx': ['py.typed'],
        'cortx.src.setup': ['*.py'],
        'cortx.src.support': ['*.py'],
      },
      long_description=long_description,
      zip_safe=False,
      python_requires='>=3.6',
      entry_points={
          'console_scripts': [
              'rgw_setup = cortx.rgw.setup.rgw_setup:main',
              'rgw_support_bundle = cortx.rgw.support.rgw_support_bundle:main',
              ]
      },
      data_files =[ ('%s/mini-provisioner' % RGW_INSTALL_PATH, mini_prov_files),
                    ('%s/bin' % RGW_INSTALL_PATH,
                    ['src/setup/rgw_setup', 'src/support/rgw_support_bundle',
                     'src/setup/rgw_service']),
                    ('%s/mini-provisioner' % RGW_INSTALL_PATH,['VERSION']),
                    ('%s/conf' % RGW_INSTALL_PATH,['conf/cortx_rgw.conf'])
                  ],
      )
