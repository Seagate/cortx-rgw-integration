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


# RGW log files to collect in support bundle
RGW_STARTUP_LOG = 'rgw_startup.log'
RGW_SETUP_LOG = 'rgw_setup.log'
RGW_SUPPORT_BUNDLE_LOG = 'rgw_support_bundle.log'
RADOSGW_ADMIN_LOG = 'radosgw-admin.log'
RGW_1_LOG = 'rgw-1.log'
# regex for following date format "1995-09-27"
LOG_DATE_REGEX = '[0-9]{4}-[0-9]{2}-[0-9]{2}'
DATETIME_DATE_REGEX = '%Y-%m-%d'
# regex for following time format "09:60:60"
LOG_TIME_REGEX = '[0-9]{2}:[0-9]{2}:[0-9]{2}'
DATETIME_TIME_REGEX = '%H:%M:%S'

COMPONENT_NAME = 'rgw'
COMPONENT_SVC_NAME = 'rgw_s3'
DECRYPTION_KEY = 'cortx'
SERVICE_NAME = f'{COMPONENT_NAME}_setup' # rgw_setup
INSTALL_PATH = '/opt/seagate/cortx'
RGW_INSTALL_PATH = f'{INSTALL_PATH}/{COMPONENT_NAME}'
ADMIN_CREATION_TIMEOUT = 600
USER_CREATION_MAX_RETRY_COUNT = 1
ADMIN_USER_CREATED = 'user_created'
DEFAULT_HTTP_PORT = '22751'
DEFAULT_HTTPS_PORT = '23001'
CONSUL_LOCK_KEY = f'component>{COMPONENT_NAME}>volatile>{COMPONENT_NAME}_lock' # component>rgw>volatile>rgw_lock
CLUSTER_ID_KEY = 'cluster>id'
CONFSTORE_FILE_HANDLER = 'ini://' # confstore uses 'ini' file handler to open any config file.e.g.ini://<filepath>

CHANGESET_URL = 'yaml:///etc/cortx/changeset.conf'
CONF_TMPL = f'{RGW_INSTALL_PATH}/conf/cortx_{COMPONENT_NAME}.conf'
LOGROTATE_TMPL = f'{RGW_INSTALL_PATH}/conf/{COMPONENT_NAME}.logrotate.tmpl'
CRON_LOGROTATE_TMPL = f'{RGW_INSTALL_PATH}/conf/logrotate.service.tmpl'
# e.g CONF_TMPL will be /opt/seagate/cortx/rgw/conf/cortx_rgw.conf
# e.g LOGROTATE_TMPL will be /opt/seagate/cortx/rgw/conf/rgw.logrotate.tmpl
RGW_CONF_FILE = f'cortx_{COMPONENT_NAME}.conf'
RELEASE_INFO_URL = f'yaml://{INSTALL_PATH}/RELEASE.INFO'
SUPPORTED_BACKEND_STORES = ['motr']
# e.g. RGW_CONFI_FILE path will be cortx_rgw.conf
LOGROTATE_DIR = "/etc/logrotate.d"
LOGROTATE_CONF = f'{LOGROTATE_DIR}/radosgw'
FREQUENCY='hourly'
CRON_DIR = f'/etc/cron.{FREQUENCY}'
CRON_LOGROTATE = f'{CRON_DIR}/logrotate'
REQUIRED_RPMS = ['cortx-hare', 'cortx-py-utils', 'ceph-radosgw']
ADMIN_PARAMETERS = {'MOTR_ADMIN_FID':'motr admin fid', 'MOTR_ADMIN_ENDPOINT':'motr admin endpoint', 'RGW_FRONTENDS': 'rgw frontends'}

# CORTX cluster confstore keys
SVC_NAME_KEY = 'node>%s>components[%s]>services[0]'
NUM_COMPONENTS_KEY = 'node>%s>num_components'
COMPONENT_NAME_KEY = 'node>%s>components[%s]>name'
LOG_PATH_KEY = 'cortx>common>storage>log'
CONFIG_PATH_KEY = 'cortx>common>storage>config'
CLIENT_INSTANCE_NAME_KEY = 'cortx>motr>clients[%s]>name'
CLIENT_INSTANCE_NUMBER_KEY = 'cortx>motr>clients[%s]>num_instances'

NODE_HOSTNAME = 'node>%s>hostname'
NODE_TYPE = 'node>%s>type'
STORAGE_SET = 'node>%s>storage_set'
STORAGE_SET_COUNT = 'cluster>num_storage_set'
STORAGE_SET_NAME = 'cluster>storage_set[%s]>name'
STORAGE_SET_NODE = 'cluster>storage_set[%s]>nodes'
AUTH_USER_KEY = f'cortx>{COMPONENT_NAME}>auth_user'
AUTH_ADMIN_KEY = f'cortx>{COMPONENT_NAME}>auth_admin'
AUTH_SECRET_KEY = f'cortx>{COMPONENT_NAME}>auth_secret'
VERSION_KEY = 'cortx>common>release>version'
CLUSTER_ID_KEY = 'cluster>id'
NODE_IDENTIFIER = 'node'
DATA_NODE_IDENTIFIER = 'num_cvg'

# SSL certificate parameters
SSL_CERT_CONFIGS = {"country" : "IN", "state" : "MH", "locality" : "Pune",
    "organization" : "Seagate Technology", "CN" : "seagate.com", "SAN": u"*.seagate.com"}
SSL_DNS_LIST = [u'*.seagate.com', u'localhost', u'*.localhost']
SSL_CERT_PATH_KEY = 'cortx>common>security>ssl_certificate'


CONSUL_ENDPOINT = 'cortx>external>consul'
CONSUL_NUM_ENDPOINT_KEY = f'{CONSUL_ENDPOINT}>num_endpoints'
CONSUL_ENDPOINT_VALUE_KEY = f'{CONSUL_ENDPOINT}>endpoints[%s]'

SVC_ENDPOINT =  f'cortx>{COMPONENT_NAME}>service'
SVC_ENDPOINT_NUM_KEY =  f'{SVC_ENDPOINT}>num_endpoints'
SVC_ENDPOINT_VALUE_KEY = f'{SVC_ENDPOINT}>endpoints[%s]'

# SVC additional paramters.(default value to be used in case of config key is missing in confstore.)
# e.g. svc_keys = {'actual_svc_config_key1':'confstore_key1', 'actual_svc_config_key2':'confstore_key2'}
SVC_CONFIG_DICT = {}

SVC_CONFIG_DICT[f'{COMPONENT_NAME} thread pool size'] = f'cortx>{COMPONENT_NAME}>thread_pool_size'
SVC_CONFIG_DICT[f'{COMPONENT_NAME} max concurrent request'] = f'cortx>{COMPONENT_NAME}>max_concurrent_request'
SVC_CONFIG_DICT[f'{COMPONENT_NAME} init timeout'] = f'cortx>{COMPONENT_NAME}>init_timeout'
SVC_CONFIG_DICT[f'{COMPONENT_NAME} gc max objs'] = f'cortx>{COMPONENT_NAME}>gc_max_objs'
SVC_CONFIG_DICT[f'{COMPONENT_NAME} gc obj min wait'] = f'cortx>{COMPONENT_NAME}>gc_obj_min_wait'
SVC_CONFIG_DICT[f'{COMPONENT_NAME} gc processor max time'] = f'cortx>{COMPONENT_NAME}>gc_processor_max_time'
SVC_CONFIG_DICT[f'{COMPONENT_NAME} gc processor period'] = f'cortx>{COMPONENT_NAME}>gc_processor_period'

# MOTR additional parameters in SVC config file.
SVC_CONFIG_DICT['motr layout id'] = f'cortx>{COMPONENT_NAME}>motr_layout_id'
SVC_CONFIG_DICT['motr unit size'] = f'cortx>{COMPONENT_NAME}>motr_unit_size'
SVC_CONFIG_DICT['motr max units per request'] = f'cortx>{COMPONENT_NAME}>motr_max_units_per_request'
SVC_CONFIG_DICT['motr max idx fetch count'] = f'cortx>{COMPONENT_NAME}>motr_max_idx_fetch_count'
SVC_CONFIG_DICT['motr max rpc msg size'] = f'cortx>{COMPONENT_NAME}>motr_max_rpc_msg_size'
SVC_CONFIG_DICT['motr reconnect interval'] = f'cortx>{COMPONENT_NAME}>motr_reconnect_interval'
SVC_CONFIG_DICT['motr reconnect retry count'] = f'cortx>{COMPONENT_NAME}>motr_reconnect_retry_count'
SVC_CONFIG_DICT['motr addb enabled'] = f'cortx>{COMPONENT_NAME}>motr_addb_enabled'


SVC_DATA_PATH_CONFSTORE_KEY = f'cortx>{COMPONENT_NAME}>data_path'
SVC_DATA_PATH_KEY = f'{COMPONENT_NAME} data path'
SVC_DATA_PATH_DEFAULT_VALUE = '/var/lib/ceph/radosgw/' # e.g. /var/lib/ceph/radosgw/<cluster-id>

# RGW config keys (cortx_rgw.conf).
CLIENT_SECTION='client'
ADMIN_SECTION = 'client.radosgw-admin'
SVC_SECTION = 'client.rgw-%s'
MOTR_ADMIN_FID_KEY = f'{ADMIN_SECTION}>{ADMIN_PARAMETERS["MOTR_ADMIN_FID"]}'
MOTR_ADMIN_ENDPOINT_KEY = f'{ADMIN_SECTION}>{ADMIN_PARAMETERS["MOTR_ADMIN_ENDPOINT"]}'
RADOS_ADMIN_LOG_FILE_KEY = f'{ADMIN_SECTION}>log file'
SVC_LOG_FILE = f'{SVC_SECTION}>log file'
RGW_FRONTEND_KEY = f'{SVC_SECTION}>{ADMIN_PARAMETERS["RGW_FRONTENDS"]}'
RGW_BACKEND_STORE_KEY = 'client>rgw backend store'
UTF_ENCODING = 'utf-8'
MOTR_MY_FID = f'{SVC_SECTION}>motr my fid'

# RGW resource limit keys
SVC_CPU_MIN_VAL_LIMIT = '250m'
SVC_MEM_MIN_VAL_LIMIT = '128Mi'
SVC_LIMIT_KEY = f'cortx>{COMPONENT_NAME}>limits'
SVC_LIMIT_NUM_SERVICES= f'{SVC_LIMIT_KEY}>num_services'
SVC_LIMIT_NAME = f'{SVC_LIMIT_KEY}>services[%s]>name'
SVC_LIMIT_CPU_MIN_KEY = f'{SVC_LIMIT_KEY}>services[%s]>cpu>min'
SVC_LIMIT_MEM_MIN_KEY = f'{SVC_LIMIT_KEY}>services[%s]>memory>min'
SVC_RESOURCE_LIMIT_MEM_VAL_SUFFIXES = [
    'K', 'Ki', 'Kib', 'M', 'Mi', 'Mib', 'G', 'Gi', 'Gib', 'T', 'Ti', 'Tib']
SVC_RESOURCE_LIMIT_MEM_VAL_SIZE_MAP = {
    "K": 1024, "M": 1024*1024, "G": 1024*1024*1024, "T": 1024*1024*1024*1024}

SVC_RESOURCE_LIMIT_CPU_VAL_SUFFIXES = ['m']
CPU_VAL_MULTIPLICATION_FACTOR = 1000
SVC_RESOURCE_LIMIT_CPU_VAL_SIZE_MAP = { "m": 1 }

class RgwEndpoint(Enum):
    """Enum class to define rgw endpoints provided by hare."""

    PROFILE_FID = {'profile_fid': 'motr profile fid'}
    MOTR_HA_EP = {'ha_ep': 'motr ha endpoint'}
    MOTR_CLIENT_EP = {'ep': 'motr my endpoint'}
    MOTR_PROCESS_FID = {'fid': 'motr my fid'}

