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
ADMIN_CREATION_TIMEOUT = 60
ADMIN_USER_CREATED = 'user_created'
CONSUL_LOCK_KEY = f'component>{COMPONENT_NAME}>volatile>{COMPONENT_NAME}_lock' # component>rgw>volatile>rgw_lock

CONF_TMPL = f'{RGW_INSTALL_PATH}/conf/cortx_{COMPONENT_NAME}.conf'
LOGROTATE_TMPL = f'{RGW_INSTALL_PATH}/conf/{COMPONENT_NAME}.logrotate.tmpl'
# e.g CONF_TMPL will be /opt/seagate/cortx/rgw/conf/cortx_rgw.conf
# e.g LOGROTATE_TMPL will be /opt/seagate/cortx/rgw/conf/rgw.logrotate.tmpl
RGW_CONF_FILE = f'cortx_{COMPONENT_NAME}.conf'
SUPPORTED_BACKEND_STORES = ['motr']
# e.g. RGW_CONFI_FILE path will be cortx_rgw.conf
LOGROTATE_DIR = "/etc/logrotate.d"
LOGROTATE_CONF = f'{LOGROTATE_DIR}/radosgw'
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
SSL_CERT_PATH_KEY = 'cortx>common>security>ssl_certificate'
SVC_ENDPOINT_KEY =  f'cortx>{COMPONENT_NAME}>s3>endpoints'

# SVC additional paramters.
# e.g. svc_keys = ['confstore_key', 'actual_svc_config_key']
SVC_THREAD_POOL_SIZE_KEY = [f'cortx>{COMPONENT_NAME}>thread_pool_size', 'thread pool size']
SVC_DATA_PATH_KEY = [f'cortx>{COMPONENT_NAME}>data_path', 'data path']
SVC_INTI_TIMEOUT_KEY = [f'cortx>{COMPONENT_NAME}>init_timeout', 'init timeout']
SVC_GC_MAX_OBJECTS_KEY = [f'cortx>{COMPONENT_NAME}>gc_max_objs', 'gc max objs']
SVC_GC_OBJECT_MIN_WAIT_KEY = [f'cortx>{COMPONENT_NAME}>gc_obj_min_wait', 'gc obj min wait']
SVC_GC_PROCESSOR_MAX_TIME_KEY = [f'cortx>{COMPONENT_NAME}>gc_processor_max_time', 'gc processor max time']
SVC_GC_PROCESSOR_PERIOD_KEY = [f'cortx>{COMPONENT_NAME}>gc_processor_period', 'gc processor period']

SVC_PARAM_MAPPING = [SVC_THREAD_POOL_SIZE_KEY, SVC_DATA_PATH_KEY,
                     SVC_INTI_TIMEOUT_KEY, SVC_GC_MAX_OBJECTS_KEY,
                     SVC_GC_OBJECT_MIN_WAIT_KEY, SVC_GC_PROCESSOR_MAX_TIME_KEY,
                     SVC_GC_PROCESSOR_PERIOD_KEY]

# MOTR additional parameters in SVC config file.
# e.g. svc_keys = ['confstore_key', 'actual_svc_config_key']

MOTR_LDAYOUT_ID_KEY = [f'cortx>{COMPONENT_NAME}>motr_layout_id', 'motr layout id']
MOTR_UNIT_SIZE_KEY = [f'cortx>{COMPONENT_NAME}>motr_unit_size', 'motr unit size']
MOTR_MAX_UNIT_PER_REQUEST_KEY = [f'cortx>{COMPONENT_NAME}>motr_max_units_per_request', 'motr max units per request']
MOTR_MAX_IDX_FETCH_COUNT_KEY = [f'cortx>{COMPONENT_NAME}>motr_max_idx_fetch_count', 'motr max idx fetch count']
MOTR_MAX_RPC_MSG_SIZE_KEY = [f'cortx>{COMPONENT_NAME}>motr_max_rpc_msg_size', 'motr max rpc msg size']
MOTR_RECONNECT_INTERVAL_KEY = [f'cortx>{COMPONENT_NAME}>motr_reconnect_interval', 'motr reconnect interval']
MOTR_RECONNECT_RETRY_COUNT_KEY = [f'cortx>{COMPONENT_NAME}>motr_reconnect_retry_count', 'motr reconnect retry count']

SVC_MOTR_PARAM_MAPPING = [MOTR_LDAYOUT_ID_KEY, MOTR_UNIT_SIZE_KEY,
                      MOTR_MAX_UNIT_PER_REQUEST_KEY, MOTR_MAX_IDX_FETCH_COUNT_KEY,
                      MOTR_MAX_RPC_MSG_SIZE_KEY, MOTR_RECONNECT_INTERVAL_KEY,
                      MOTR_RECONNECT_RETRY_COUNT_KEY]

class RgwEndpoint(Enum):
    """Enum class to define rgw endpoints provided by hare."""

    MOTR_PROFILE_FID = 'motr profile fid'
    MOTR_HA_EP       = 'motr ha endpoint'
    MOTR_CLIENT_EP   = 'motr my endpoint'
    MOTR_PROCESS_FID = 'motr my fid'


