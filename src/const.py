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

SERVICE_NAME = 'rgw_setup'
INSTALL_PATH = '/opt/seagate/cortx'
RGW_INSTALL_PATH = f'{INSTALL_PATH}/rgw'
CEPH_CONF_TMPL = f'{RGW_INSTALL_PATH}/conf/ceph.conf'
CEPH_CONF = '/etc/ceph/ceph.conf'
CEPH_ADMIN_KEYRING = '/etc/ceph/ceph.client.admin.keyring'
CEPH_RPMS = ['ceph-radosgw', 'ceph-common', 'ceph-base', 'gperftools-libs',
            'libcephfs2', 'libicu', 'liboath','librabbitmq','librados2',
            'libradosstriper1','librbd1','librgw2','libunwind', 'mailcap',
            'python3-ceph-argparse','python3-ceph-common', 'python3-cephfs',
            'python3-rados','python3-rbd','python3-rgw']
CORTX_RPMS = ['cortx-hare', 'cortx-motr-devel', 'cortx-motr', 'cortx-py-utils']
LOG_PATH_KEY = 'cortx>common>storage>log'
