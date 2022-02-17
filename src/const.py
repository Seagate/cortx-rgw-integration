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

from enum import Enum

COMPONENT_NAME = 'rgw'
DECRYPTION_KEY = 'cortx'
SERVICE_NAME = f'{COMPONENT_NAME}_setup' # rgw_setup
INSTALL_PATH = '/opt/seagate/cortx'
RGW_INSTALL_PATH = f'{INSTALL_PATH}/{COMPONENT_NAME}'

RGW_CONF_TMPL = f'{RGW_INSTALL_PATH}/conf/cortx_{COMPONENT_NAME}.conf'
# e.g RGW_CONF_TMPL will be /opt/seagate/cortx/rgw/cof/cortx_rgw.conf
RGW_CONF_FILE = f'cortx_{COMPONENT_NAME}.conf'
# e.g. RGW_CONFI_FILE path will be cortx_rgw.conf
CRASHDUMP_DIR = '/var/lib/ceph/crash'
REQUIRED_RPMS = ['cortx-hare', 'cortx-py-utils', 'ceph-radosgw']
ADMIN_PARAMETERS = {'MOTR_ADMIN_FID':'motr admin fid', 'MOTR_ADMIN_ENDPOINT':'motr admin endpoint', 'RGW_FRONTENDS': 'rgw frontends'}

# CORTX cluster confstore keys
LOG_PATH_KEY = 'cortx>common>storage>log'
CONFIG_PATH_KEY = 'cortx>common>storage>config'
CLIENT_INSTANCE_NAME_KEY = 'cortx>motr>clients[%s]>name'
CLIENT_INSTANCE_NUMBER_KEY = 'cortx>motr>clients[%s]>num_instances'
CONSUL_ENDPOINT_KEY = 'cortx>external>consul>endpoints'

# SSL certificate parameters
SSL_CERT_CONFIGS = {"country" : "IN", "state" : "MH", "locality" : "Pune",
    "organization" : "Seagate Technology", "CN" : "seagate.com"}
SSL_DNS_LIST = [u'*.seagate.com', u'localhost', u'*.localhost']

class RgwEndpoint(Enum):
    """Enum class to define rgw endpoints provided by hare."""

    MOTR_PROFILE_FID = 'motr profile fid'
    MOTR_HA_EP       = 'motr ha endpoint'
    MOTR_CLIENT_EP   = 'motr my endpoint'
    MOTR_PROCESS_FID = 'motr my fid'
    MOTR_CLIENT_PORT = 'motr client port'

