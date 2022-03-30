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
COMPONENT_SVC_NAME = 'rgw_s3'
DECRYPTION_KEY = 'cortx'
SERVICE_NAME = f'{COMPONENT_NAME}_setup' # rgw_setup
INSTALL_PATH = '/opt/seagate/cortx'
RGW_INSTALL_PATH = f'{INSTALL_PATH}/{COMPONENT_NAME}'
# TODO: Revisit after Motr delay issue resolved, seen while admin creation, for CORTX cluster with 15 nodes.
ADMIN_CREATION_TIMEOUT = 600
ADMIN_USER_CREATED = 'user_created'
DEFAULT_HTTP_PORT = '22751'
DEFAULT_HTTPS_PORT = '23001'
CONSUL_LOCK_KEY = f'component>{COMPONENT_NAME}>volatile>{COMPONENT_NAME}_lock' # component>rgw>volatile>rgw_lock
CLUSTER_ID_KEY = 'cluster>id'

CONF_TMPL = f'{RGW_INSTALL_PATH}/conf/cortx_{COMPONENT_NAME}.conf'
LOGROTATE_TMPL = f'{RGW_INSTALL_PATH}/conf/{COMPONENT_NAME}.logrotate.tmpl'
CRON_LOGROTATE_TMPL = f'{RGW_INSTALL_PATH}/conf/logrotate.service.tmpl'
# e.g CONF_TMPL will be /opt/seagate/cortx/rgw/conf/cortx_rgw.conf
# e.g LOGROTATE_TMPL will be /opt/seagate/cortx/rgw/conf/rgw.logrotate.tmpl
RGW_CONF_FILE = f'cortx_{COMPONENT_NAME}.conf'
SUPPORTED_BACKEND_STORES = ['motr']
# e.g. RGW_CONFI_FILE path will be cortx_rgw.conf
LOGROTATE_DIR = "/etc/logrotate.d"
LOGROTATE_CONF = f'{LOGROTATE_DIR}/radosgw'
FREQUENCY='hourly'
CRON_DIR = f'/etc/cron.{FREQUENCY}'
CRON_LOGROTATE = f'{CRON_DIR}/logrotate'
CRASHDUMP_DIR = '/var/lib/ceph/crash'
REQUIRED_RPMS = ['cortx-hare', 'cortx-py-utils', 'ceph-radosgw']
ADMIN_PARAMETERS = {'MOTR_ADMIN_FID':'motr admin fid', 'MOTR_ADMIN_ENDPOINT':'motr admin endpoint', 'RGW_FRONTENDS': 'rgw frontends'}

# CORTX cluster confstore keys
LOG_PATH_KEY = 'cortx>common>storage>log'
CONFIG_PATH_KEY = 'cortx>common>storage>config'
CLIENT_INSTANCE_NAME_KEY = 'cortx>motr>clients[%s]>name'
CLIENT_INSTANCE_NUMBER_KEY = 'cortx>motr>clients[%s]>num_instances'
CONSUL_ENDPOINT_KEY = 'cortx>external>consul>endpoints'
NODE_HOSTNAME = 'node>%s>hostname'
NODE_TYPE = 'node>%s>type'
STORAGE_SET = 'node>%s>storage_set'
STORAGE_SET_COUNT = 'cluster>storage_set_count'
STORAGE_SET_NAME = 'cluster>storage_set[%s]>name'
STORAGE_SET_NODE = 'cluster>storage_set[%s]>nodes'
AUTH_USER_KEY = f'cortx>{COMPONENT_NAME}>auth_user'
AUTH_ADMIN_KEY = f'cortx>{COMPONENT_NAME}>auth_admin'
AUTH_SECRET_KEY = f'cortx>{COMPONENT_NAME}>auth_secret'
CLUSTER_ID_KEY = 'cluster>id'
DATA_NODE = 'data_node'

# SSL certificate parameters
SSL_CERT_CONFIGS = {"country" : "IN", "state" : "MH", "locality" : "Pune",
    "organization" : "Seagate Technology", "CN" : "seagate.com", "SAN": u"*.seagate.com"}
SSL_DNS_LIST = [u'*.seagate.com', u'localhost', u'*.localhost']
SSL_CERT_PATH_KEY = 'cortx>common>security>ssl_certificate'
SVC_ENDPOINT_KEY =  f'cortx>{COMPONENT_NAME}>service>endpoints'

# SVC additional paramters.(default value to be used in case of config key is missing in confstore.)
# e.g. svc_keys = ['confstore_key', 'actual_svc_config_key', 'default_value']
SVC_THREAD_POOL_SIZE_KEY = [f'cortx>{COMPONENT_NAME}>thread_pool_size', f'{COMPONENT_NAME} thread pool size', '10']
SVC_INTI_TIMEOUT_KEY = [f'cortx>{COMPONENT_NAME}>init_timeout', f'{COMPONENT_NAME} init timeout', '300']
SVC_GC_MAX_OBJECTS_KEY = [f'cortx>{COMPONENT_NAME}>gc_max_objs', f'{COMPONENT_NAME} gc max objs', '32']
SVC_GC_OBJECT_MIN_WAIT_KEY = [f'cortx>{COMPONENT_NAME}>gc_obj_min_wait', f'{COMPONENT_NAME} gc obj min wait', '1800']
SVC_GC_PROCESSOR_MAX_TIME_KEY = [f'cortx>{COMPONENT_NAME}>gc_processor_max_time', f'{COMPONENT_NAME} gc processor max time', '3600']
SVC_GC_PROCESSOR_PERIOD_KEY = [f'cortx>{COMPONENT_NAME}>gc_processor_period', f'{COMPONENT_NAME} gc processor period', '3600']

SVC_PARAM_MAPPING = [SVC_THREAD_POOL_SIZE_KEY, SVC_INTI_TIMEOUT_KEY,
                     SVC_GC_MAX_OBJECTS_KEY, SVC_GC_OBJECT_MIN_WAIT_KEY,
                     SVC_GC_PROCESSOR_MAX_TIME_KEY, SVC_GC_PROCESSOR_PERIOD_KEY]


SVC_DATA_PATH_CONFSTORE_KEY = f'cortx>{COMPONENT_NAME}>data_path'
SVC_DATA_PATH_KEY = f'{COMPONENT_NAME} data path'
# e.g. default value will be appended by cluster-id hence kept it seperatly
SVC_DATA_PATH_DEFAULT_VALUE = '/var/lib/ceph/radosgw/' # e.g. /var/lib/ceph/radosgw/<cluster-id>

# MOTR additional parameters in SVC config file.
# default value to be used in case of config key is missing in confstore.
# e.g. svc_keys = ['confstore_key', 'actual_svc_config_key', 'default_value']

MOTR_LDAYOUT_ID_KEY = [f'cortx>{COMPONENT_NAME}>motr_layout_id', 'motr layout id', '9']
MOTR_UNIT_SIZE_KEY = [f'cortx>{COMPONENT_NAME}>motr_unit_size', 'motr unit size', '1048576']
MOTR_MAX_UNIT_PER_REQUEST_KEY = [f'cortx>{COMPONENT_NAME}>motr_max_units_per_request', 'motr max units per request', '8']
MOTR_MAX_IDX_FETCH_COUNT_KEY = [f'cortx>{COMPONENT_NAME}>motr_max_idx_fetch_count', 'motr max idx fetch count', '30']
MOTR_MAX_RPC_MSG_SIZE_KEY = [f'cortx>{COMPONENT_NAME}>motr_max_rpc_msg_size', 'motr max rpc msg size', '524288']
MOTR_RECONNECT_INTERVAL_KEY = [f'cortx>{COMPONENT_NAME}>motr_reconnect_interval', 'motr reconnect interval', '4']
MOTR_RECONNECT_RETRY_COUNT_KEY = [f'cortx>{COMPONENT_NAME}>motr_reconnect_retry_count', 'motr reconnect retry count', '15']

SVC_MOTR_PARAM_MAPPING = [MOTR_LDAYOUT_ID_KEY, MOTR_UNIT_SIZE_KEY,
                      MOTR_MAX_UNIT_PER_REQUEST_KEY, MOTR_MAX_IDX_FETCH_COUNT_KEY,
                      MOTR_MAX_RPC_MSG_SIZE_KEY, MOTR_RECONNECT_INTERVAL_KEY,
                      MOTR_RECONNECT_RETRY_COUNT_KEY]

# RGW config keys (cortx_rgw.conf).
ADMIN_SECTION = 'client.radosgw-admin'
SVC_SECTION = 'client.rgw-%s'
MOTR_ADMIN_FID_KEY = f'{ADMIN_SECTION}>{ADMIN_PARAMETERS["MOTR_ADMIN_FID"]}'
MOTR_ADMIN_ENDPOINT_KEY = f'{ADMIN_SECTION}>{ADMIN_PARAMETERS["MOTR_ADMIN_ENDPOINT"]}'
RADOS_ADMIN_LOG_FILE_KEY = f'{ADMIN_SECTION}>log file'
SVC_LOG_FILE = f'{SVC_SECTION}>log file'
RGW_FRONTEND_KEY = f'{SVC_SECTION}>{ADMIN_PARAMETERS["RGW_FRONTENDS"]}'
RGW_BACKEND_STORE_KEY = 'client>rgw backend store'
UTF_ENCODING = 'utf-8'


class RgwEndpoint(Enum):
    """Enum class to define rgw endpoints provided by hare."""

    PROFILE_FID = {'profile_fid': 'motr profile fid'}
    MOTR_HA_EP = {'ha_ep': 'motr ha endpoint'}
    MOTR_CLIENT_EP = {'ep': 'motr my endpoint'}
    MOTR_PROCESS_FID = {'fid': 'motr my fid'}



