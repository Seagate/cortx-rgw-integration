#!/usr/bin/python3

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
import time
import errno
import json
from urllib.parse import urlparse

from cortx.utils.security.certificate import Certificate
from cortx.utils.errors import SSLCertificateError
from cortx.utils.validator.v_pkg import PkgV
from cortx.utils.conf_store import Conf, MappedConf
from cortx.utils.conf_store.error import ConfError
from cortx.utils.process import SimpleProcess
from cortx.utils.schema.release import Release
from cortx.utils.log import Log
from cortx.rgw.setup.error import SetupError
from cortx.rgw.setup.rgw_service import RgwService
from cortx.utils.security.cipher import Cipher, CipherInvalidToken
from cortx.rgw import const
from cortx.utils.common import ExponentialBackoff


class Rgw:
    """Represents RGW and Performs setup related actions."""

    _machine_id = Conf.machine_id
    _conf_idx = f'{const.COMPONENT_NAME}_config'   # e.g. rgw_config

    @staticmethod
    def validate(phase: str):
        """Perform validations."""

        Log.info(f'validations started for {phase} phase.')

        if phase == 'post_install':
            # Perform RPM validations
            for rpms in [const.REQUIRED_RPMS]:
                PkgV().validate('rpms', rpms)
            Log.info(f'All RGW required RPMs are installed on {Rgw._machine_id} node.')
        elif phase == 'prepare':
            Rgw._file_exist(const.CONF_TMPL)

        Log.info(f'validations completed for {phase} phase.')

        return 0

    @staticmethod
    def post_install(conf: MappedConf):
        """Performs post install operations."""

        Log.info('PostInstall phase completed.')
        return 0

    @staticmethod
    def prepare(conf: MappedConf):
        """Prepare for operations required before RGW can be configured."""

        Log.info('Prepare phase started.')

        try:
            config_path = Rgw._get_rgw_config_path(conf)
            tmpl_idx = f'{const.COMPONENT_NAME}_conf_tmpl'  # e.g. rgw_conf_tmpl
            tmpl_url = const.CONFSTORE_FILE_HANDLER + const.CONF_TMPL
            Rgw._load_rgw_config(tmpl_idx, tmpl_url)
            confstore_url = const.CONFSTORE_FILE_HANDLER + config_path
            Rgw._load_rgw_config(Rgw._conf_idx, confstore_url)
            Conf.copy(tmpl_idx, Rgw._conf_idx)
            Conf.save(Rgw._conf_idx)
            Log.info(f'{const.CONF_TMPL} config copied to {config_path}')

        except Exception as e:
            raise SetupError(errno.EINVAL, f'Error ocurred while fetching node ip, {e}')

        Log.info('Prepare phase completed.')

        return 0

    @staticmethod
    def config(conf: MappedConf):
        """Performs configurations."""

        Log.info('Config phase started.')
        Rgw._check_consul_connection(conf)
        config_file = Rgw._get_rgw_config_path(conf)
        if not os.path.exists(config_file):
            raise SetupError(errno.EINVAL, f'"{config_file}" config file is not present.')

        # Create ssl certificate
        Rgw._generate_ssl_cert(conf)

        # Create svc config
        Rgw._create_svc_config(conf)

        # Create motr trace directory for collecting m0trace files
        # in case admin user creation issue during mini-provisioner execution.
        Log.info('Creating motr trace directory for collecting m0trace files..')
        log_path = Rgw._get_log_dir_path(conf)
        motr_trace_dir = os.path.join(log_path, 'motr_trace_files')
        os.makedirs(motr_trace_dir, exist_ok=True)
        os.environ['M0_TRACE_DIR'] = motr_trace_dir
        Log.info('Created motr trace directory : %s' % os.environ.get('M0_TRACE_DIR'))

        # Read Motr HA(HAX) endpoint from data pod using hctl fetch-fids and update in config file
        # Use remote hax endpoint running on data pod which will be available during rgw
        # config phase since data pod starts before server pod.
        # Try HAX endpoint from data pod of same node first & if it doesnt work,
        # from other data pods in cluster
        Rgw._update_hax_endpoint_and_create_admin(conf)
        Log.info('Config phase completed.')

        return 0

    @staticmethod
    def start(conf: MappedConf, index: str):
        """Create rgw admin user and start rgw service."""

        Log.info(f'Configure logrotate for {const.COMPONENT_NAME} at path: {const.LOGROTATE_CONF}')
        Rgw._logrotate_generic(conf)

        # Before starting service,Verify backend store value=motr in rgw config file.
        Rgw._verify_backend_store_value(conf)

        # Create motr trace & addb stob dirctory.
        # Collect fid value of motr to create addb value.
        config_file = Rgw._get_rgw_config_path(conf)
        confstore_url = const.CONFSTORE_FILE_HANDLER + config_file
        Rgw._load_rgw_config(Rgw._conf_idx, confstore_url)
        motr_fid_key = const.MOTR_MY_FID % index
        motr_fid_value = Conf.get(Rgw._conf_idx, motr_fid_key)
        log_path = Rgw._get_log_dir_path(conf)
        motr_trace_dir = os.path.join(log_path, 'motr_trace_files')
        addb_dir = os.path.join(log_path, f'addb_files-{motr_fid_value}')
        os.makedirs(motr_trace_dir, exist_ok=True)
        os.makedirs(addb_dir, exist_ok=True)

        Log.info('Starting radosgw service.')
        log_file = os.path.join(log_path, f'{const.COMPONENT_NAME}_startup.log')

        RgwService.start(conf, config_file, log_file, motr_trace_dir, index)
        Log.info("Started radosgw service.")

        return 0

    @staticmethod
    def init(conf: MappedConf):
        """Perform initialization."""

        Log.info('Init phase completed.')
        return 0

    @staticmethod
    def test(conf: MappedConf, plan: str):
        """Perform configuration testing."""

        Log.info('Test phase completed.')
        return 0

    @staticmethod
    def reset(conf: MappedConf):
        """Remove/Delete all the data/logs that was created by user/testing."""

        Log.info('Reset phase completed.')
        return 0

    @staticmethod
    def cleanup(conf: MappedConf, pre_factory: bool = False):
        """Remove/Delete all the data that was created after post install."""
        config_path = Rgw._get_rgw_config_path(conf)
        if os.path.exists(config_path):
            os.remove(config_path)
        Log.info('Cleanup phase completed.')
        return 0

    @staticmethod
    def _update_rgw_property(conf: MappedConf, config_index:str, config_key: str, config_val: str):
        """Add/Update key in rgw config file."""
        for rgw_config_key, confstore_key in const.SVC_CONFIG_DICT.items():
            if confstore_key == config_key:
                Conf.set(config_index, f'{const.CLIENT_SECTION}>{rgw_config_key}', config_val)
        Conf.save(config_index)

    @staticmethod
    def _remove_rgw_property(conf: MappedConf, config_index:str, config_key: str):
        """Remove specific key from rgw config file."""
        for rgw_config_key, confstore_key in const.SVC_CONFIG_DICT.items():
            if confstore_key == config_key:
                Conf.delete(config_index, f'{const.CLIENT_SECTION}>{rgw_config_key}')
        Conf.save(config_index)

    @staticmethod
    def upgrade(conf: MappedConf, changeset_path: str):
        """Perform upgrade steps."""
        Log.info('Upgrade phase started.')
        conf_dir = Rgw._get_rgw_config_dir(conf)
        svc_conf_file = Rgw._get_rgw_config_path(conf)

        # Load changeset file
        changeset_index="rgw_changeset_index"
        if not os.path.exists(changeset_path):
             raise SetupError(errno.EINVAL, f'Changeset file is missing for Upgrade.')
        Rgw._load_rgw_config(changeset_index, changeset_path)

        # Get all changed keys from changeset file.
        changeset_all_keys=Conf.get_keys(changeset_index)

        # Load deployed rgw config and take a backup.
        Rgw._load_rgw_config(Rgw._conf_idx, const.CONFSTORE_FILE_HANDLER + svc_conf_file)
        deployed_version = conf.get(const.VERSION_KEY)
        conf_bkp_file = os.path.join(conf_dir, const.RGW_CONF_FILE + f'.{deployed_version}')

        try:
            # Cleaning up failure config of previous upgrade.
            if os.path.exists(conf_bkp_file):
                os.remove(conf_bkp_file)

            # create backup of existing config file
            os.copy(svc_conf_file, conf_bkp_file)

            # Handle svc key & Gconf key mapping
            for key in changeset_all_keys:
                if key.stratswith('new') :
                    # Handle addition of new key
                    value = Conf.get(changeset_index, key)
                    key =key.split('new>')[1]
                    Rgw._update_rgw_property(conf, Rgw._conf_idx, key, new_val)
                elif key.stratswith('changed'):
                    # Handle updation of existing key
                    value = Conf.get(changeset_index, key)
                    key =key.split('changed>')[1]
                    old_val, new_val = value.split('|')
                    Rgw._update_rgw_property(conf, Rgw._conf_idx, key, new_val)
                elif key.stratswith('deleted'):
                    # Handle deletion of existing key
                    key =key.split('deleted>')[1]
                    Rgw._remove_rgw_property(conf, Rgw._conf_idx, key)

            # Update upgraded release version.
            updated_version = Release(const.RELEASE_INFO_URL).get_release_version()
            Conf.set(Rgw._conf_idx, 'release>version', updated_version)

            # Save updated config file.
            Conf.save(Rgw._conf_idx)

            # delete backup file after upgrade.
            os.remove(conf_bkp_file)

        except Exception as e:
            raise SetupError(errno.EINVAL, f'Upgrade failed with error: {e}')

        Log.info('Upgrade phase completed.')
        return 0

    @staticmethod
    def _create_svc_config(conf: MappedConf):
        """Create svc config"""
        svc_name = Rgw._get_svc_name(conf)
        client_instance_count = Rgw._get_num_client_instances(conf, svc_name)
        Log.info('fetching endpoint values from hctl fetch-fids cmd.')
        # For running rgw service and radosgw-admin tool,
        # we are using same endpoints fetched from hctl fetch-fids cmd as default endpoints,
        # given radosgw-admin tool & rgw service not expected to run simultaneously.

        # Update motr fid,endpoint config in cortx_rgw.conf.
        instance = 1
        while instance <= client_instance_count:
            service_endpoints = Rgw._parse_endpoint_values(
                conf, instance, client_instance_count, svc_name)
            Log.debug('Validating endpoint entries provided by fetch-fids cmd')
            Rgw._validate_endpoint_paramters(service_endpoints)
            Log.info('Validated endpoint entries provided by fetch-fids cmd successfully.')

            Log.info('Updating endpoint values in rgw config file.')
            Rgw._update_rgw_config_with_endpoints(conf, service_endpoints, instance)
            instance = instance + 1

        # Add additional parameters of SVC & Motr to config file.
        Rgw._update_svc_config(conf, 'client', const.SVC_CONFIG_DICT)
        Rgw._update_svc_data_path_value(conf, 'client')

        # Before user creation,Verify backend store value=motr in rgw config file.
        Rgw._verify_backend_store_value(conf)

        Log.info(f'Configure logrotate for {const.COMPONENT_NAME} at path: {const.LOGROTATE_CONF}')
        Rgw._logrotate_generic(conf)

    @staticmethod
    def _get_consul_url(conf: MappedConf, seq: int = 0):
        """Return consul url."""
        http_endpoints = Rgw._fetch_endpoint_url(conf, const.CONSUL_ENDPOINT_KEY, 'http')
        consul_fqdn = http_endpoints[seq].split(':')[1]
        consul_url = 'consul:' + consul_fqdn + ':8500'
        return consul_url

    @staticmethod
    @ExponentialBackoff(exception=Exception, tries=4)
    def _check_consul_connection(conf: MappedConf):
        import socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        consul_url = Rgw._get_consul_url(conf).split('//')[-1]
        host, port = consul_url.split(':')
        result = sock.connect_ex((host, int(port)))
        if result != 0:
            raise SetupError(errno.EINVAL, f"Consul server {host:port} not reachable")

    @staticmethod
    def _fetch_endpoint_url(conf: MappedConf, confstore_endpoint_key: str, endpoint_type: str):
        """Fetch endpoint url based on endpoint type from cortx config."""
        endpoints = Rgw._get_cortx_conf(conf, confstore_endpoint_key)
        endpoints_values = list(filter(lambda x: urlparse(x).scheme == endpoint_type, endpoints))
        if len(endpoints_values) == 0:
            raise SetupError(errno.EINVAL,
                f'{endpoint_type} endpoint is not specified in the conf.'
                f' Listed endpoints: {endpoints_values}')
        return endpoints_values

    @staticmethod
    def _file_exist(file_path: str):
        """Check if a file is exists."""
        if not os.path.exists(file_path):
            raise SetupError(errno.EINVAL,
                f'{file_path} file not exists.')

    @staticmethod
    def _load_rgw_config(conf_idx: str, conf_url: str):
        """Add/Updated key-values in given config."""
        try:
            if conf_url is None:
                raise SetupError(errno.EINVAL, 'Conf url is None.')
            Conf.load(conf_idx, conf_url, fail_reload=False)
        except (AssertionError, ConfError) as e:
            raise SetupError(errno.EINVAL,
                f'Error occurred while adding the key in {conf_url} config. {e}')

    @staticmethod
    def _get_rgw_config_path(conf: MappedConf):
        """Return RGW config file path."""
        rgw_config_dir = Rgw._get_rgw_config_dir(conf)
        os.makedirs(rgw_config_dir, exist_ok=True)
        rgw_conf_file_path = os.path.join(rgw_config_dir, const.RGW_CONF_FILE)
        return rgw_conf_file_path

    @staticmethod
    def _get_rgw_config_dir(conf: MappedConf):
        """Return RGW config directory path."""
        config_path = Rgw._get_cortx_conf(conf, const.CONFIG_PATH_KEY)
        rgw_config_dir = os.path.join(config_path, const.COMPONENT_NAME, Rgw._machine_id)
        return rgw_config_dir

    @staticmethod
    def _get_log_dir_path(conf: MappedConf):
        """Return log dir path."""
        log_path = Rgw._get_cortx_conf(conf, const.LOG_PATH_KEY)
        log_dir_path = os.path.join(log_path, const.COMPONENT_NAME, Rgw._machine_id)
        os.makedirs(log_dir_path, exist_ok=True)
        return log_dir_path

    @staticmethod
    def _create_rgw_user(conf: MappedConf):
        """Create RGW admin user."""
        user_name = Rgw._get_cortx_conf(conf, const.AUTH_USER_KEY)
        access_key = Rgw._get_cortx_conf(conf, const.AUTH_ADMIN_KEY)
        auth_secret = Rgw._get_cortx_conf(conf, const.AUTH_SECRET_KEY)
        err_str = f'user: {user_name} exists'
        timeout_str = f'timed out after {const.ADMIN_CREATION_TIMEOUT} seconds'
        # decrypt secret key.
        try:
            cluster_id = Rgw._get_cortx_conf(conf, const.CLUSTER_ID_KEY)
            cipher_key = Cipher.gen_key(cluster_id, const.DECRYPTION_KEY)
            password = Cipher.decrypt(cipher_key, auth_secret.encode(const.UTF_ENCODING))
            password = password.decode(const.UTF_ENCODING)
        except CipherInvalidToken as e:
            raise SetupError(errno.EINVAL, f'auth_secret decryption failed. {e}')
        rgw_config = Rgw._get_rgw_config_path(conf)
        create_usr_cmd = f'radosgw-admin user create --uid={user_name} --access-key \
            {access_key} --secret {password} --display-name="{user_name}" \
            --caps="users=*;metadata=*;usage=*;zone=*;info=*;user=*;roles=*;user-policy=*;buckets=*" \
            -c {rgw_config} -n client.radosgw-admin --no-mon-config'
        _, err, rc, = SimpleProcess(create_usr_cmd).run(timeout=const.ADMIN_CREATION_TIMEOUT)
        if rc == 0:
            Log.info(f'RGW admin user {user_name} is created.')
            return 0
        elif rc != 0:
            err = err.decode(const.UTF_ENCODING) if isinstance(err, bytes) else err
            if err_str in err:
                Log.info(f'RGW admin user {user_name} is already created,'
                    ' Skipping user creation.')
                return 0
            elif timeout_str in err:
                Log.info('RGW user creation process exceeding timeout value - '
                    f'{const.ADMIN_CREATION_TIMEOUT} seconds. Skipping user creation on this node.')
                return rc
            else:
                Log.error(f'"{create_usr_cmd}" failed with error {err}.')
                return rc

    @staticmethod
    def _parse_endpoint_values(conf: MappedConf, instance: int, client_instance_count: int, svc_name: str):
        """Fetch endpoint values from hctl fetch-fids."""
        hare_config_dir = Rgw._get_hare_config_path(conf)
        fetch_fids_cmd = f'hctl fetch-fids -c {hare_config_dir}'
        decoded_out = Rgw._run_fetch_fid_cmd(fetch_fids_cmd)
        Rgw._validate_hctl_cmd_response(decoded_out, svc_name)

        endpoints = [comp for comp in decoded_out if comp['name'] == svc_name]
        # RGW client_instance_count should be equal/less than the
        # no of rgw config elements present in hctl fetch-fids output.
        if len(endpoints) < client_instance_count:
            raise SetupError(errno.EINVAL,
                f'The count of {svc_name} elements in hctl-fetch-fids o/p '
                f'does not match with the {svc_name} client instance count.')
        # Fetch endpoints based on instance,
        # for eg. for instance=1 read 0th index rgw config list from output and so on.
        index = instance - 1
        endpoints = endpoints[index]

        for ep_key, ep_value in const.RgwEndpoint.__members__.items():
            if list(ep_value.value.keys())[0] in endpoints:
                endpoints[ep_key] = endpoints.pop(list(ep_value.value.keys())[0])

        return endpoints

    @staticmethod
    def _update_rgw_config_with_endpoints(conf: MappedConf, endpoints: dict, instance: int):
        """Update endpoints,port and log path values to rgw config file."""
        config_file = Rgw._get_rgw_config_path(conf)
        confstore_url = const.CONFSTORE_FILE_HANDLER + config_file
        Rgw._load_rgw_config(Rgw._conf_idx, confstore_url)
        log_path = Rgw._get_log_dir_path(conf)
        service_instance_log_file = os.path.join(log_path, f'{const.COMPONENT_NAME}-{instance}.log')
        radosgw_admin_log_file = os.path.join(log_path, 'radosgw-admin.log')

        # Update version in conf file.
        version = Rgw._get_cortx_conf(conf, const.VERSION_KEY)
        Conf.set(Rgw._conf_idx, 'release>version', version)
        # Update client.radosgw-admin section only once,
        # Update this with same config that is define for 1st instance.
        if instance == 1:
            for key, ep_value in const.RgwEndpoint.__members__.items():
                value = list(ep_value.value.values())[0]
                Conf.set(Rgw._conf_idx, f'{const.ADMIN_SECTION}>{value}', endpoints[key])
            Conf.set(Rgw._conf_idx, const.MOTR_ADMIN_FID_KEY,
                endpoints[const.RgwEndpoint.MOTR_PROCESS_FID.name])
            Conf.set(Rgw._conf_idx, const.MOTR_ADMIN_ENDPOINT_KEY,
                endpoints[const.RgwEndpoint.MOTR_CLIENT_EP.name])
            Conf.set(Rgw._conf_idx, const.RADOS_ADMIN_LOG_FILE_KEY, radosgw_admin_log_file)

        # Create separate section for each service instance in cortx_rgw.conf file.
        for key, ep_value in const.RgwEndpoint.__members__.items():
            value = list(ep_value.value.values())[0]
            Conf.set(Rgw._conf_idx, f'{const.SVC_SECTION % instance}>{value}', endpoints[key])
        Conf.set(Rgw._conf_idx, const.SVC_LOG_FILE % instance, service_instance_log_file)
        # Removed port increment support for service multiple instances.
        # (in case of multiple instances port value needs to be incremented.)
        http_port = Rgw._get_service_port(conf, 'http')
        https_port = Rgw._get_service_port(conf, 'https')
        ssl_cert_path = Rgw._get_cortx_conf(conf, const.SSL_CERT_PATH_KEY)
        Conf.set(Rgw._conf_idx, const.RGW_FRONTEND_KEY % instance,
            f'beast port={http_port} ssl_port={https_port} ssl_certificate={ssl_cert_path} ssl_private_key={ssl_cert_path}')
        Conf.save(Rgw._conf_idx)

    @staticmethod
    def _get_service_port(conf: MappedConf, protocol: str):
        """Return rgw service port value."""
        port = None
        endpoints = conf.get(const.SVC_ENDPOINT_KEY)
        if endpoints:
            svc_endpoints = list(filter(lambda x: urlparse(x).scheme == protocol, endpoints))
            port = urlparse(svc_endpoints[0]).port
            Log.info(f'{protocol} port value - {port}')
        else:
            # If endpoint is not present, use default port value.
            if protocol == 'http':
                port = const.DEFAULT_HTTP_PORT
            elif protocol == 'https':
                port = const.DEFAULT_HTTPS_PORT
            Log.info(f'{const.SVC_ENDPOINT_KEY} is not available in cluster.conf,'
                f' using the default value. {protocol} - {port}')
        return port

    @staticmethod
    def _validate_endpoint_paramters(endpoints: dict):
        """Validate endpoint values fetched from hctl fetch-fids cmd."""

        for key, _ in const.RgwEndpoint.__members__.items():
            if key not in endpoints:
                raise SetupError(errno.EINVAL, f'Failed to validate hare endpoint values.'
                    f'endpoint {key} is not present.')

        for ept_key, ept_value in endpoints.items():
            if ept_value == '':
                raise SetupError(errno.EINVAL, f'Invalid values for {ept_key}: {ept_value}')

    @staticmethod
    def _validate_hctl_cmd_response(decoded_out: list, svc_name: str):
        """Validate hctl command response."""
        try:
            next(endpoint for endpoint in decoded_out if endpoint['name'] == svc_name)
        except StopIteration:
            raise SetupError(errno.EINVAL, 'Invalid %s endpoint values', svc_name)

    @staticmethod
    def _get_hare_config_path(conf: MappedConf):
        """Return config path of hare component."""
        base_config_path = Rgw._get_cortx_conf(conf, const.CONFIG_PATH_KEY)
        hare_config_path = os.path.join(base_config_path, 'hare',
            'config', Rgw._machine_id)
        return hare_config_path

    @staticmethod
    def _get_num_client_instances(conf: MappedConf, svc_name: str):
        """Read number of client instances."""
        client_idx = 0
        num_instances = 1
        while conf.get(const.CLIENT_INSTANCE_NAME_KEY % client_idx) is not None:
            name = Rgw._get_cortx_conf(conf, const.CLIENT_INSTANCE_NAME_KEY % client_idx)
            if name == svc_name:
                num_instances = int(Rgw._get_cortx_conf(conf, const.CLIENT_INSTANCE_NUMBER_KEY % client_idx))
                break
            client_idx = client_idx + 1
        return num_instances

    @staticmethod
    def _get_cortx_conf(conf: MappedConf, key: str, default_value = None):
        """Read value from cluster config for given key"""
        val = conf.get(key)
        if val is None:
            if default_value is None:
                raise SetupError(errno.EINVAL, f'Value for {key} key is None.')
            else:
                val = default_value
        return val

    @staticmethod
    def _get_svc_name(conf: MappedConf):
        """Read service name from cluster.conf"""
        svc_name = None
        num_component = Rgw._get_cortx_conf(conf, const.NUM_COMPONENTS_KEY % Rgw._machine_id)
        for idx in range(0, num_component):
            if (Rgw._get_cortx_conf(conf,
                const.COMPONENT_NAME_KEY % (Rgw._machine_id, idx)) == const.COMPONENT_NAME):
                svc_name = Rgw._get_cortx_conf(conf,
                    const.SVC_NAME_KEY % (Rgw._machine_id, idx), const.COMPONENT_NAME)
                break
        Log.info(f'Service name for {const.COMPONENT_NAME} is {svc_name}')
        return svc_name

    @staticmethod
    def _generate_ssl_cert(conf: MappedConf):
        """Generate SSL certificate."""
        ssl_cert_path = Rgw._get_cortx_conf(conf, const.SSL_CERT_PATH_KEY)
        if not os.path.exists(ssl_cert_path):
            # Generate SSL cert.
            Log.info(f'"https" is enabled and SSL certificate is not present at {ssl_cert_path}.')
            Log.info('Generating SSL certificate.')
            try:
                ssl_cert_configs = const.SSL_CERT_CONFIGS
                ssl_cert_obj = Certificate.init('ssl')
                ssl_cert_obj.generate(
                    cert_path=ssl_cert_path, dns_list=const.SSL_DNS_LIST, **ssl_cert_configs)
            except SSLCertificateError as e:
                raise SetupError(errno.EINVAL, f'Failed to generate self signed ssl certificate: {e}')

    @staticmethod
    def _update_hax_endpoint(conf: MappedConf, data_pod_hostname: str):
        """Update hax endpoint values in rgw config file."""
        Log.info('Reading motr_ha_endpoint from data pod')

        if not data_pod_hostname:
            raise SetupError(errno.EINVAL, 'Invalid data pod hostname: %s', data_pod_hostname)

        hare_config_dir = Rgw._get_hare_config_path(conf)
        fetch_fids_cmd = f'hctl fetch-fids -c {hare_config_dir} --node {data_pod_hostname}'
        decoded_out = Rgw._run_fetch_fid_cmd(fetch_fids_cmd, data_pod_hostname)
        Rgw._validate_hctl_cmd_response(decoded_out, 'hax')
        motr_ha_endpoint = [endpoints['ep'] for endpoints in decoded_out \
            if 'hax' in endpoints.values()][0]
        Log.info(f'Fetched motr_ha_endpoint from data pod. Endpoint: {motr_ha_endpoint}')

        config_path = Rgw._get_rgw_config_path(conf)
        confstore_url = const.CONFSTORE_FILE_HANDLER + config_path
        Rgw._load_rgw_config(Rgw._conf_idx, confstore_url)
        ha_ep_key = list(const.RgwEndpoint.MOTR_HA_EP.value.values())[0]
        Conf.set(Rgw._conf_idx, f'client.radosgw-admin>{ha_ep_key}', motr_ha_endpoint)
        Conf.save(Rgw._conf_idx)

        Log.info(f'Updated motr_ha_endpoint in config file {config_path}')

    @staticmethod
    def _run_fetch_fid_cmd(fetch_fids_cmd: str, data_pod_hostname: str = None):
        """Run hctl fetch-fids command through SimpleProcess."""
        out, err, rc = SimpleProcess(fetch_fids_cmd).run()
        if rc != 0:
            if data_pod_hostname:
                Log.error(f'Unable to read fid information for hostname: '
                    f'{data_pod_hostname}. {err}')
                raise SetupError(rc, 'Unable to read fid information for hostname: '
                    '%s. %s', data_pod_hostname, err)
            else:
                Log.error(f'Unable to read fid information. {err}')
                raise SetupError(rc, 'Unable to read fid information. %s', err)

        decoded_out = json.loads(out.decode(const.UTF_ENCODING))

        return decoded_out

    @staticmethod
    def _create_admin_on_current_node(conf: MappedConf, current_data_node: str):
        try:
            Rgw._update_hax_endpoint(conf, current_data_node)
            Log.info('Creating admin user.')
            # Before creating user check if user is already created.
            user_status = Rgw._create_rgw_user(conf)
            return user_status
        except Exception:
            return -1

    @staticmethod
    def _update_hax_endpoint_and_create_admin(conf: MappedConf):
        """Update motr_ha(hax) endpoint values to rgw config file and create admin."""
        # admin user should be created only on one node.
        # 1. While creating admin user, global lock created in consul kv store.
        # (rgw_consul_index, cortx>rgw>volatile>rgw_lock, machine_id)
        # 2. Before creating admin user.
        #    a. Check for rgw_lock in consul kv store
        #    b. Create user only if lock value is equal to **self** machine_id
        # 3. If user creation attempt failed from this node, delete the lock
        #    so other node can acquire the lock and try user creation.
        # 4. If user creation is successful, update lock value to 'user_created'.

        rgw_consul_idx = f'{const.COMPONENT_NAME}_consul_idx'
        # Get consul url from cortx config.
        consul_url = Rgw._get_consul_url(conf)
        # Check for rgw_lock in consul kv store.
        Log.info('Checking for rgw lock in consul kv store.')
        Rgw._load_rgw_config(rgw_consul_idx, consul_url)
        rgw_lock = Rgw._get_lock(rgw_consul_idx)
        if rgw_lock is True:
            # TODO: Find a way to get current data pod hostname on server node.
            # current_data_node = socket.gethostname().replace('server', 'data')
            # user_status = Rgw._create_admin_on_current_node(conf, current_data_node)

            # if user_status == 0:
            #    Log.info(f'User creation is successful on "{Rgw._machine_id}" node.')
            #    Rgw._set_consul_kv(rgw_consul_idx, const.CONSUL_LOCK_KEY, const.ADMIN_USER_CREATED)
            # else:
            data_pod_hostnames = Rgw._get_data_nodes(conf)
            #    if len(data_pod_hostnames) == 1 and current_data_node == data_pod_hostnames[0]:
            #        Log.error('Admin user creation failed')
            #        Rgw._delete_consul_kv(rgw_consul_idx, const.CONSUL_LOCK_KEY)
            #        raise SetupError(user_status, 'Admin user creation failed on'
            #            f' "{Rgw._machine_id}" node, with all data pods - {data_pod_hostnames}')

            #    data_pod_hostnames.remove(current_data_node)
            for data_pod_hostname in data_pod_hostnames:
                try:
                    Rgw._update_hax_endpoint(conf, data_pod_hostname)
                except SetupError as e:
                    Log.debug(f'Error occured while updating hax endpoints. {e}')
                    continue
                status = Rgw._create_rgw_user(conf)
                if status == 0:
                    Log.info(f'User creation is successful on "{Rgw._machine_id}" node.')
                    Rgw._set_consul_kv(rgw_consul_idx, const.CONSUL_LOCK_KEY, const.ADMIN_USER_CREATED)
                    break
                else:
                    if data_pod_hostname == data_pod_hostnames[-1]:
                        Log.error(f'Admin user creation failed with error code - {status}')
                        Rgw._delete_consul_kv(rgw_consul_idx, const.CONSUL_LOCK_KEY)
                        raise SetupError(status, 'Admin user creation failed on'
                            f' "{Rgw._machine_id}" node, with all data pods - {data_pod_hostnames}')


    @staticmethod
    def _get_data_nodes(conf: MappedConf):
        """Return all data nodes hostname"""
        storage_set = Rgw._get_cortx_conf(conf, const.STORAGE_SET % Rgw._machine_id)
        storage_set_count = Rgw._get_cortx_conf(conf, const.STORAGE_SET_COUNT)
        machine_ids = []
        for storage_set_index in range(0, storage_set_count):
            if Rgw._get_cortx_conf(conf,
                const.STORAGE_SET_NAME % storage_set_index) == storage_set:
                machine_ids = Rgw._get_cortx_conf(
                    conf, const.STORAGE_SET_NODE % storage_set_index)
        data_pod_hostnames = [Rgw._get_cortx_conf(conf, const.NODE_HOSTNAME % machine_id)
            for machine_id in machine_ids if
            Rgw._get_cortx_conf(conf, const.NODE_TYPE % machine_id) == const.DATA_NODE]
        return data_pod_hostnames

    @staticmethod
    def _get_lock(consul_idx: str):
        """Get lock from consul kv."""
        # if in case try-catch block code executed at the same time on all the nodes,
        # then all nodes will try to update rgw lock-key in consul, after updating key
        # it will wait for sometime(time.sleep(3)) and in next iteration all nodes will
        # get lock value as node-id of node who has updated the lock key at last.
        # and then only that node will perform the user creation operation.
        rgw_lock = False
        while True:
            try:
                rgw_lock_val = Conf.get(consul_idx, const.CONSUL_LOCK_KEY)
                Log.info(f'{const.CONSUL_LOCK_KEY} value - {rgw_lock_val}')
                if rgw_lock_val is None:
                    Log.info(f'Setting consul kv store value for key :{const.CONSUL_LOCK_KEY}'
                            f' and value as :{Rgw._machine_id}')
                    Rgw._set_consul_kv(consul_idx, const.CONSUL_LOCK_KEY, Rgw._machine_id)
                    continue
                elif rgw_lock_val == Rgw._machine_id:
                    Log.info('Required lock already possessed, proceeding with RGW '
                        f'admin user creation on node {rgw_lock_val}')
                    rgw_lock = True
                    break
                elif rgw_lock_val != Rgw._machine_id:
                    if rgw_lock_val == const.ADMIN_USER_CREATED:
                        Log.info('User is already created.')
                        break
                    Log.info(f'RGW lock is acquired by "{rgw_lock_val}" node.')
                    Log.info(f'Waiting for user creation to complete on "{rgw_lock_val}" node')
                    time.sleep(3)
                    continue

            except Exception as e:
                Log.error('Exception occured while connecting to consul service'
                          f' endpoint {e}')
                break
        return rgw_lock

    @staticmethod
    def _set_consul_kv(consul_idx: str, key: str, value: str):
        """Update key value pair in consul kv store."""
        Conf.set(consul_idx, key, value)
        Conf.save(consul_idx)
        time.sleep(3)
        Log.info(f'Updated consul kv store - {key} - {value}.')

    @staticmethod
    def _delete_consul_kv(consul_idx: str, key: str):
        """Delete key value pair from consul kv store."""
        Log.debug(f'Deleting rgw_lock key {key}.')
        Conf.delete(consul_idx, key)
        Log.info(f'{key} key is deleted')

    @staticmethod
    def _logrotate_generic(conf: MappedConf):
        """ Configure logrotate utility for rgw logs."""
        log_file_path = Rgw._get_log_dir_path(conf)
        # Configure the cron job on hourly frequency for RGW log files.
        try:
            with open(const.CRON_LOGROTATE_TMPL, 'r') as f:
                content = f.read()
            with open(const.CRON_LOGROTATE, 'w') as f:
                f.write(content)
        except Exception as e:
            Log.error(f"Failed to configure cron job for logrotate at {const.FREQUENCY} basis."
                      f"ERROR:{e}")
        # create radosgw logrotate file.
        # For eg:
        # filepath='/etc/logrotate.d/radosgw'
        old_file = os.path.join(const.LOGROTATE_DIR, 'ceph')
        if os.path.exists(old_file):
            os.remove(old_file)
        try:
            with open(const.LOGROTATE_TMPL, 'r') as f:
                content = f.read()
            content = content.replace('TMP_LOG_PATH', log_file_path)
            with open(const.LOGROTATE_CONF, 'w') as f:
                f.write(content)
            Log.info(f'{const.LOGROTATE_TMPL} file copied to {const.LOGROTATE_CONF}')
        except Exception as e:
            Log.error(f"Failed to configure logrotate for {const.COMPONENT_NAME}. ERROR:{e}")
        # start cron.d service
        try:
            os.system(f"chmod +x {const.CRON_LOGROTATE}")
            os.system("/usr/sbin/crond start")
        except Exception as e:
            Log.error(f"Failed to start the crond service for {const.COMPONENT_NAME}. ERROR:{e}")

    @staticmethod
    def _verify_backend_store_value(conf: MappedConf):
        """Verify backed store value as motr."""
        config_file = Rgw._get_rgw_config_path(conf)
        confstore_url = const.CONFSTORE_FILE_HANDLER + config_file
        Rgw._load_rgw_config(Rgw._conf_idx, confstore_url)
        backend_store = Conf.get(Rgw._conf_idx, const.RGW_BACKEND_STORE_KEY)
        if not backend_store in const.SUPPORTED_BACKEND_STORES:
            raise SetupError(errno.EINVAL,
                f'Supported rgw backend store are {const.SUPPORTED_BACKEND_STORES},'
                f' currently configured one is {backend_store}')

    @staticmethod
    def _update_svc_config(conf: MappedConf, client_section: str, config_key_mapping: dict):
        """Update config properties from confstore to rgw config file."""
        svc_config_file = Rgw._get_rgw_config_path(conf)
        confstore_url = const.CONFSTORE_FILE_HANDLER + svc_config_file
        Rgw._load_rgw_config(Rgw._conf_idx, confstore_url)
        Log.info(f'updating parameters to {client_section} in {svc_config_file}')

        for config_key, confstore_key in config_key_mapping.items():
            default_value = Conf.get(Rgw._conf_idx, f'{client_section}>{config_key}')
            if confstore_key is None:
                Log.info(f'config key:{config_key} not found in rgw key mapping.\
                    hence using default value as {default_value} specified in config file.')
                continue
            else:
                # fetch actual value of parameter from confstore.
                # if config key/value is missing in confstore then use default value mentioned in config file.
                config_value = conf.get(confstore_key)
                if config_value is not None:
                    Log.info(f'Setting config key :{config_key} with value:{config_value} at {client_section} section')
                    Conf.set(Rgw._conf_idx, f'{client_section}>{config_key}', str(config_value))
                else :
                    Log.info(f'GConfig entry is missing for config key :{config_key}.\
                        hence using default value as {default_value} specified in config file.')
                    continue

        Conf.save(Rgw._conf_idx)
        Log.info(f'added paramters to {client_section} successfully..')

    @staticmethod
    def _update_svc_data_path_value(conf: MappedConf, client_section: str):
        "Update svc config file with data path key which needs pre-processing values incase of default values."
        # Fetch cluster-id
        cluster_id = Rgw._get_cortx_conf(conf, const.CLUSTER_ID_KEY)
        svc_config_file = Rgw._get_rgw_config_path(conf)
        confstore_url = const.CONFSTORE_FILE_HANDLER + svc_config_file
        Rgw._load_rgw_config(Rgw._conf_idx, confstore_url)
        Log.info(f'updating data_path paramter to {client_section} in {svc_config_file}')

        # Create data path's default value e.g. /var/lib/ceph/radosgw/<cluster-id>
        data_path_default_value = const.SVC_DATA_PATH_DEFAULT_VALUE + cluster_id
        confstore_data_path_value = conf.get(const.SVC_DATA_PATH_CONFSTORE_KEY)
        if confstore_data_path_value is not None:
           Log.info(f'Setting config key :{const.SVC_DATA_PATH_KEY} with value:{confstore_data_path_value}\
               at {client_section} section')
           Conf.set(Rgw._conf_idx, f'{client_section}>{const.SVC_DATA_PATH_KEY}', str(confstore_data_path_value))
        else:
           Log.info(f'GConfig entry is missing for config key :{const.SVC_DATA_PATH_KEY}.\
                        hence using default value as {data_path_default_value} specified in config file.')
           Conf.set(Rgw._conf_idx, f'{client_section}>{const.SVC_DATA_PATH_KEY}', str(data_path_default_value))

        Conf.save(Rgw._conf_idx)
        Log.info(f'added config parameters to {client_section} successfully..')
