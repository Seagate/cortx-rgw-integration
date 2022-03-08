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
import glob
import json
import socket
from urllib.parse import urlparse
from cortx.utils.security.certificate import Certificate
from cortx.utils.errors import SSLCertificateError
from cortx.utils.validator.v_pkg import PkgV
from cortx.utils.conf_store import Conf, MappedConf
from cortx.utils.conf_store.error import ConfError
from cortx.utils.process import SimpleProcess
from cortx.utils.log import Log
from cortx.rgw.setup.error import SetupError
from cortx.rgw.setup.rgw_service import RgwService
from cortx.utils.security.cipher import Cipher, CipherInvalidToken
from cortx.rgw.const import (
    REQUIRED_RPMS, RGW_CONF_TMPL, RGW_CONF_FILE, CONFIG_PATH_KEY,
    CLIENT_INSTANCE_NAME_KEY, CLIENT_INSTANCE_NUMBER_KEY, CONSUL_ENDPOINT_KEY,
    COMPONENT_NAME, ADMIN_PARAMETERS, LOG_PATH_KEY, DECRYPTION_KEY,
    SSL_CERT_CONFIGS, SSL_DNS_LIST, RgwEndpoint, LOGROTATE_TMPL, LOGROTATE_DIR,
    LOGROTATE_CONF, SUPPORTED_BACKEND_STORES, ADMIN_CREATION_TIMEOUT,
    ADMIN_USER_CREATED, CONSUL_LOCK_KEY)


class Rgw:
    """Represents RGW and Performs setup related actions."""

    _machine_id = Conf.machine_id
    _rgw_conf_idx = f'{COMPONENT_NAME}_config'   # e.g. rgw_config

    @staticmethod
    def validate(phase: str):
        """Perform validations."""

        Log.info(f'validations started for {phase} phase.')

        if phase == 'post_install':
            # Perform RPM validations
            for rpms in [REQUIRED_RPMS]:
                PkgV().validate('rpms', rpms)
            Log.info(f'All RGW required RPMs are installed on {Rgw._machine_id} node.')
        elif phase == 'prepare':
            Rgw._file_exist(RGW_CONF_TMPL)

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
            rgw_config_path = Rgw._get_rgw_config_path(conf)
            rgw_tmpl_idx = f'{COMPONENT_NAME}_conf_tmpl'  # e.g. rgw_conf_tmpl
            rgw_tmpl_url = f'ini://{RGW_CONF_TMPL}'
            Rgw._load_rgw_config(rgw_tmpl_idx, rgw_tmpl_url)
            Rgw._load_rgw_config(Rgw._rgw_conf_idx, f'ini://{rgw_config_path}')
            Conf.copy(rgw_tmpl_idx, Rgw._rgw_conf_idx)
            Conf.save(Rgw._rgw_conf_idx)
            Log.info(f'{RGW_CONF_TMPL} config copied to {rgw_config_path}')

        except Exception as e:
            raise SetupError(errno.EINVAL, f'Error ocurred while fetching node ip, {e}')

        Log.info('Prepare phase completed.')

        return 0

    @staticmethod
    def config(conf: MappedConf):
        """Performs configurations."""

        Log.info('Config phase started.')

        config_file = Rgw._get_rgw_config_path(conf)
        if not os.path.exists(config_file):
            raise SetupError(errno.EINVAL, f'"{config_file}" config file is not present.')

        # Create ssl certificate
        Rgw._generate_ssl_cert(conf)

        Log.info('create symbolic link of FID config files started')
        sysconfig_file_path = Rgw._get_sysconfig_file_path(conf)
        client_instance_count = Rgw._get_num_client_instances(conf)
        Rgw._create_symbolic_link_fid(client_instance_count, sysconfig_file_path)
        Log.info('create symbolic link of FID config files completed')
        Log.info('fetching endpoint values from hare sysconfig file.')
        # For running rgw service and radosgw-admin tool,
        # we are using same endpoints mentioned in first symlink file 'rgw-1' as default endpoints,
        # given radosgw-admin tool & rgw service not expected to run simultaneously.

        # Update motr fid,endpoint config in cortx_rgw.conf, based on instance based symlink.
        instance = 1
        while instance <= client_instance_count:
            client_instance_file = sysconfig_file_path + f'/{COMPONENT_NAME}-{instance}'
            service_endpoints = Rgw._parse_endpoint_values(client_instance_file)  # e.g.(rgw-1)
            Log.debug(f'Validating endpoint entries provided by "{client_instance_file}" file.')
            Rgw._validate_endpoint_paramters(service_endpoints)
            Log.info(f'Validated endpoint entries provided by "{client_instance_file}" file successfully.')

            Log.info('Updating endpoint values in rgw config file.')
            Rgw._update_rgw_config_with_endpoints(conf, service_endpoints, instance)
            instance = instance + 1

        # Before user creation,Verify backend store value=motr in rgw config file.
        Rgw._verify_backend_store_value(conf)

        # Read Motr HA(HAX) endpoint from data pod using hctl fetch-fids and update in config file
        # Use remote hax endpoint running on data pod which will be available during rgw
        # config phase since data pod starts before server pod.
        # Try HAX endpoint from data pod of same node first & if it doesnt work,
        # from other data pods in cluster
        Rgw._update_hax_endpoint_and_create_admin(conf)

        Log.info(f'Configure logrotate for {COMPONENT_NAME} at path: {LOGROTATE_CONF}')
        Rgw._logrotate_generic(conf)
        Log.info('Config phase completed.')
        return 0

    @staticmethod
    def start(conf: MappedConf, index: str):
        """Create rgw admin user and start rgw service."""

        Log.info(f'Configure logrotate for {COMPONENT_NAME} at path: {LOGROTATE_CONF}')
        Rgw._logrotate_generic(conf)
        # Before starting service,Verify backend store value=motr in rgw config file.
        Rgw._verify_backend_store_value(conf)
        log_path = Rgw._get_log_dir_path(conf)
        motr_trace_dir = os.path.join(log_path, 'motr_trace_files')
        os.makedirs(motr_trace_dir, exist_ok=True)

        Log.info('Starting radosgw service.')
        log_file = os.path.join(log_path, f'{COMPONENT_NAME}_startup.log')
        config_file = Rgw._get_rgw_config_path(conf)
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
        rgw_config_path = Rgw._get_rgw_config_path(conf)
        if os.path.exists(rgw_config_path):
            os.remove(rgw_config_path)
        Log.info('Cleanup phase completed.')
        return 0

    @staticmethod
    def upgrade(conf: MappedConf):
        """Perform upgrade steps."""

        Log.info('Upgrade phase completed.')
        return 0

    @staticmethod
    def _get_consul_url(conf: MappedConf, seq: int = 0):
        """Return consul url."""

        endpoints = Rgw._get_cortx_conf(conf, CONSUL_ENDPOINT_KEY)
        http_endpoints = list(filter(lambda x: urlparse(x).scheme == 'http', endpoints))
        if len(http_endpoints) == 0:
            raise SetupError(errno.EINVAL,
                'consul http endpoint is not specified in the conf.'
                f' Listed endpoints: {endpoints}')
        # Relace 'http' with 'consul' and port - 8500 in endpoint string.
        consul_fqdn = http_endpoints[seq].split(':')[1]
        consul_url = 'consul:' + consul_fqdn + ':8500'
        return consul_url

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
        rgw_conf_file_path = os.path.join(rgw_config_dir, RGW_CONF_FILE)
        return rgw_conf_file_path

    @staticmethod
    def _get_rgw_config_dir(conf: MappedConf):
        """Return RGW config directory path."""
        config_path = Rgw._get_cortx_conf(conf, CONFIG_PATH_KEY)
        rgw_config_dir = os.path.join(config_path, COMPONENT_NAME, Rgw._machine_id)
        return rgw_config_dir

    @staticmethod
    def _get_log_dir_path(conf: MappedConf):
        """Return log dir path."""
        log_path = Rgw._get_cortx_conf(conf, LOG_PATH_KEY)
        log_dir_path = os.path.join(log_path, COMPONENT_NAME, Rgw._machine_id)
        os.makedirs(log_dir_path, exist_ok=True)
        return log_dir_path

    @staticmethod
    def _create_rgw_user(conf: MappedConf):
        """Create RGW admin user."""
        user_name = Rgw._get_cortx_conf(conf, f'cortx>{COMPONENT_NAME}>auth_user')
        access_key = Rgw._get_cortx_conf(conf, f'cortx>{COMPONENT_NAME}>auth_admin')
        auth_secret = Rgw._get_cortx_conf(conf, f'cortx>{COMPONENT_NAME}>auth_secret')
        err_str = f'user: {user_name} exists'
        # decrypt secret key.
        try:
            cluster_id = Rgw._get_cortx_conf(conf, 'cluster>id')
            cipher_key = Cipher.gen_key(cluster_id, DECRYPTION_KEY)
            password = Cipher.decrypt(cipher_key, auth_secret.encode('utf-8'))
            password = password.decode('utf-8')
        except CipherInvalidToken as e:
            raise SetupError(errno.EINVAL, f'auth_secret decryption failed. {e}')
        rgw_config = Rgw._get_rgw_config_path(conf)
        create_usr_cmd = f'sudo radosgw-admin user create --uid={user_name} --access-key \
            {access_key} --secret {password} --display-name="{user_name}" \
            --caps="users=*;metadata=*;usage=*;zone=*" \
            -c {rgw_config} -n client.radosgw-admin --no-mon-config'
        _, err, rc, = SimpleProcess(create_usr_cmd).run(timeout=ADMIN_CREATION_TIMEOUT)
        if rc == 0:
            Log.info(f'RGW admin user {user_name} is created.')
            return 0
        elif rc != 0:
            if err and err_str in err.decode():
                Log.info(f'RGW admin user {user_name} is already created. \
                    skipping user creation.')
                return 0
            else:
                Log.error(f'"{create_usr_cmd}" failed with error {err}.')
                return rc

    @staticmethod
    def _create_symbolic_link_fid(client_instance_count: int, sysconfig_file_path: str):
        """ Create symbolic link of FID sysconfig files."""
        hare_generated_fid_files = Rgw._get_files(sysconfig_file_path + f'/{COMPONENT_NAME}-0x*')
        count = len(hare_generated_fid_files)
        Log.info(f'{COMPONENT_NAME} FID file count : {count}')
        Log.info(f'Number of {COMPONENT_NAME} client instances - {client_instance_count}')
        if count < client_instance_count:
            raise SetupError(errno.EINVAL,
                f'HARE-sysconfig file does not match {COMPONENT_NAME} client instances.')

        # Create symbolic links of rgw-fid files created by hare.
        # e.g rgw-0x7200000000000001\:0x9c -> rgw-1 , rgw-0x7200000000000001\:0x5b -> rgw-2
        index = 1
        for src_path in hare_generated_fid_files:
            file_name = f'{COMPONENT_NAME}-' + str(index)      # e.g. rgw-1 for rgw file
            dst_path = os.path.join(sysconfig_file_path, file_name)
            Rgw._create_symbolic_link(src_path, dst_path)
            index += 1

    @staticmethod
    def _create_symbolic_link(src_path: str, dst_path: str):
        """create symbolic link."""
        Log.debug(f'symbolic link source path: {src_path}')
        Log.debug(f'symbolic link destination path: {dst_path}')
        if os.path.exists(dst_path):
            Log.debug('symbolic link is already present')
            os.unlink(dst_path)
            Log.debug('symbolic link is unlinked')
        os.symlink(src_path, dst_path)
        Log.info(f'symbolic link created successfully from {src_path} to {dst_path}')

    @staticmethod
    def _parse_endpoint_values(client_instance_file: str):
        """Read sysconfig file generated by hare
         1) Read symblink file '{client_instance_file}' as default endpoints in config phase.
         2) fetch endpoint values for running radosgw-admin tool.
        """
        endpoints = {}
        with open(client_instance_file) as ep_file:
            for line in ep_file:
                ep_name, ep_value = line.partition('=')[::2]
                endpoints[ep_name.strip()] = str(ep_value.strip())

        return endpoints

    @staticmethod
    def _update_rgw_config_with_endpoints(conf: MappedConf, endpoints: dict, instance: int):
        """Update endpoints,port and log path values to rgw config file."""
        rgw_config_dir = Rgw._get_rgw_config_dir(conf)
        rgw_config_file = os.path.join(rgw_config_dir, RGW_CONF_FILE)
        Rgw._load_rgw_config(Rgw._rgw_conf_idx, f'ini://{rgw_config_file}')
        log_path = Rgw._get_log_dir_path(conf)
        service_instance_log_file = os.path.join(log_path, f'{COMPONENT_NAME}-{instance}.log')

        # Update client.radosgw-admin section only once,
        # Update this with same config that is define for 1st instance.
        if instance == 1:
            radosgw_admin_log_file = os.path.join(
                log_path, 'radosgw-admin.log')
            for ep_value, key in RgwEndpoint._value2member_map_.items():
                Conf.set(Rgw._rgw_conf_idx,
                    f'client.radosgw-admin>{ep_value}', endpoints[key.name])
            Conf.set(Rgw._rgw_conf_idx,
                f'client.radosgw-admin>{ADMIN_PARAMETERS["MOTR_ADMIN_FID"]}',
                endpoints[RgwEndpoint.MOTR_PROCESS_FID.name])
            Conf.set(
                Rgw._rgw_conf_idx,
                f'client.radosgw-admin>{ADMIN_PARAMETERS["MOTR_ADMIN_ENDPOINT"]}',
                endpoints[RgwEndpoint.MOTR_CLIENT_EP.name])
            Conf.set(Rgw._rgw_conf_idx, f'client.radosgw-admin>log file', radosgw_admin_log_file)

        # Create separate section for each service instance in cortx_rgw.conf file.
        for ep_value, key in RgwEndpoint._value2member_map_.items():
            Conf.set(Rgw._rgw_conf_idx, f'client.rgw-{instance}>{ep_value}', endpoints[key.name])
        Conf.set(Rgw._rgw_conf_idx, f'client.rgw-{instance}>log file', service_instance_log_file)
        # For each instance increase port value by 1.
        # for eg. for 1st instance. port=8000
        # for 2nd instance port=8000 + 1
        # port = <port> + (instance - 1)
        # TODO: read port value from endpoint url define in cluster.conf
        port = 8000
        port = port + (instance - 1)
        ssl_port = 8443
        ssl_port = ssl_port + (instance - 1)
        ssl_cert_path = Rgw._get_cortx_conf(conf, 'cortx>common>security>ssl_certificate')
        Conf.set(
            Rgw._rgw_conf_idx,
            f'client.rgw-{instance}>{ADMIN_PARAMETERS["RGW_FRONTENDS"]}',
            f'beast port={port} ssl_port={ssl_port} ssl_certificate={ssl_cert_path} ssl_private_key={ssl_cert_path}')
        Conf.save(Rgw._rgw_conf_idx)

    @staticmethod
    def _validate_endpoint_paramters(endpoints: dict):
        """Validate endpoint values provided by hare sysconfig file."""

        for ep_value, key in RgwEndpoint._value2member_map_.items():
            if key.name not in endpoints or not endpoints.get(key.name):
                raise SetupError(errno.EINVAL, f'Failed to validate hare endpoint values.'
                    f'endpoint {key.name} or its value is not present.')

    @staticmethod
    def _get_files(substr_pattern: str):
        """Return all files present in path that matches with given pattern."""
        list_matching = []
        for name in glob.glob(substr_pattern):
            list_matching.append(name)
        return list_matching

    @staticmethod
    def _get_sysconfig_file_path(conf: MappedConf):
        """Return hare generated sysconfig file path."""
        base_config_path = Rgw._get_cortx_conf(conf, CONFIG_PATH_KEY)
        sysconfig_file_path = os.path.join(base_config_path, COMPONENT_NAME,
            'sysconfig', Rgw._machine_id)
        return sysconfig_file_path

    @staticmethod
    def _get_num_client_instances(conf: MappedConf):
        """Read number of client instances."""
        client_idx = 0
        num_instances = 1
        while conf.get(CLIENT_INSTANCE_NAME_KEY % client_idx) is not None:
            name = Rgw._get_cortx_conf(conf, CLIENT_INSTANCE_NAME_KEY % client_idx)
            if name == COMPONENT_NAME:
                num_instances = int(Rgw._get_cortx_conf(conf, CLIENT_INSTANCE_NUMBER_KEY % client_idx))
                break
            client_idx = client_idx + 1
        return num_instances

    @staticmethod
    def _get_cortx_conf(conf: MappedConf, key: str):
        """Read value from cluster config for given key"""
        val = conf.get(key)
        if val is None:
            raise SetupError(errno.EINVAL, f'Value for {key} key is None.')
        return val

    @staticmethod
    def _generate_ssl_cert(conf: MappedConf):
        """Generate SSL certificate."""
        ssl_cert_path = Rgw._get_cortx_conf(conf, 'cortx>common>security>ssl_certificate')
        endpoints = Rgw._get_cortx_conf(conf, 'cortx>rgw>s3>endpoints')
        https_endpoints = list(filter(lambda x: urlparse(x).scheme == 'https', endpoints))
        if len(https_endpoints) > 0 and not os.path.exists(ssl_cert_path):
            # Generate SSL cert.
            Log.info(f'"https" is enabled and SSL certificate is not present at {ssl_cert_path}.')
            Log.info('Generating SSL certificate.')
            try:
                SSL_DNS_LIST.append(urlparse(https_endpoints[0]).hostname)
                ssl_cert_configs = SSL_CERT_CONFIGS
                ssl_cert_obj = Certificate.init('ssl')
                ssl_cert_obj.generate(
                    cert_path=ssl_cert_path, dns_list=SSL_DNS_LIST, **ssl_cert_configs)
            except SSLCertificateError as e:
                raise SetupError(errno.EINVAL, f'Failed to generate self signed ssl certificate: {e}')

    @staticmethod
    def _update_hax_endpoint(conf: MappedConf, data_pod_hostname: str):
        """Update hax endpoint values in rgw config file."""
        Log.info('Reading motr_ha_endpoint from data pod')

        if not data_pod_hostname:
            raise SetupError(errno.EINVAL, 'Invalid data pod hostname: %s', data_pod_hostname)

        config_path = Rgw._get_cortx_conf(conf, CONFIG_PATH_KEY)
        hare_config_dir = os.path.join(config_path, 'hare', 'config', Rgw._machine_id)

        fetch_fids_cmd = f'hctl fetch-fids -c {hare_config_dir} --node {data_pod_hostname}'
        out, err, rc = SimpleProcess(fetch_fids_cmd).run()
        if rc != 0:
            Log.error(f'Unable to read fid information for hostname: '
                f'{data_pod_hostname}. {err}')
            raise SetupError(rc, 'Unable to read fid information for hostname: '
                '%s. %s', data_pod_hostname, err)
        decoded_out = json.loads(out.decode('utf-8'))
        motr_ha_endpoint = [endpoints['ep'] for endpoints in decoded_out \
            if 'hax' in endpoints.values()][0]
        Log.info(f'Fetched motr_ha_endpoint from data pod. Endpoint: {motr_ha_endpoint}')

        rgw_config_path = Rgw._get_rgw_config_path(conf)
        Rgw._load_rgw_config(Rgw._rgw_conf_idx, f'ini://{rgw_config_path}')
        Conf.set(Rgw._rgw_conf_idx, \
            f'client.radosgw-admin>{RgwEndpoint.MOTR_HA_EP.value}', motr_ha_endpoint)
        Conf.save(Rgw._rgw_conf_idx)

        Log.info(f'Updated motr_ha_endpoint in config file {rgw_config_path}')

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

        rgw_lock = False
        rgw_consul_idx = f'{COMPONENT_NAME}_consul_idx'
        # Get consul url from cortx config.
        consul_url = Rgw._get_consul_url(conf)
        # Check for rgw_lock in consul kv store.
        Log.info('Checking for rgw lock in consul kv store.')
        Rgw._load_rgw_config(rgw_consul_idx, consul_url)
        # if in case try-catch block code executed at the same time on all the nodes,
        # then all nodes will try to update rgw lock-key in consul, after updating key
        # it will wait for sometime(time.sleep(3)) and in next iteration all nodes will
        # get lock value as node-id of node who has updated the lock key at last.
        # and then only that node will perform the user creation operation.
        while True:
            try:
                rgw_lock_val = Conf.get(rgw_consul_idx, CONSUL_LOCK_KEY)
                Log.info(f'{CONSUL_LOCK_KEY} value - {rgw_lock_val}')
                if rgw_lock_val is None:
                    Log.info(f'Setting consul kv store value for key :{CONSUL_LOCK_KEY}'
                            f' and value as :{Rgw._machine_id}')
                    Rgw._set_consul_kv(rgw_consul_idx, CONSUL_LOCK_KEY, Rgw._machine_id)
                    continue
                elif rgw_lock_val == Rgw._machine_id:
                    Log.info('Required lock already possessed, proceeding with RGW '
                        f'admin user creation on node {rgw_lock_val}')
                    rgw_lock = True
                    break
                elif rgw_lock_val != Rgw._machine_id:
                    if rgw_lock_val == ADMIN_USER_CREATED:
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
        if rgw_lock is True:
            current_data_node = socket.gethostname().replace('server', 'data')
            user_status = Rgw._create_admin_on_current_node(conf, current_data_node)

            if user_status == 0:
                Log.info(f'User creation is successful on "{Rgw._machine_id}" node.')
                Rgw._set_consul_kv(rgw_consul_idx, CONSUL_LOCK_KEY, ADMIN_USER_CREATED)
            else:
                machine_ids = Rgw._get_cortx_conf(conf, 'cluster>storage_set[0]>nodes')
                data_pod_hostnames = [Rgw._get_cortx_conf(conf,
                    f'node>{machine_id}>hostname') for machine_id in machine_ids if
                    Rgw._get_cortx_conf(conf, f'node>{machine_id}>type') == 'data_node']
                if len(data_pod_hostnames) == 1 and current_data_node == data_pod_hostnames[0]:
                    Log.error('Admin user creation failed')
                    Rgw._delete_consul_kv(rgw_consul_idx, CONSUL_LOCK_KEY)
                    raise SetupError(user_status, 'Admin user creation failed on'
                        f' "{Rgw._machine_id}" node, with all data pods - {data_pod_hostnames}')

                data_pod_hostnames.remove(current_data_node)
                for data_pod_hostname in data_pod_hostnames:
                    try:
                        Rgw._update_hax_endpoint(conf, data_pod_hostname)
                    except Exception:
                        continue
                    status = Rgw._create_rgw_user(conf)
                    if status == 0:
                        Log.info(f'User creation is successful on "{Rgw._machine_id}" node.')
                        Rgw._set_consul_kv(rgw_consul_idx, CONSUL_LOCK_KEY, ADMIN_USER_CREATED)
                        break
                    else:
                        if data_pod_hostname == data_pod_hostnames[-1]:
                            Log.error(f'Admin user creation failed with error code - {status}')
                            Rgw._delete_consul_kv(rgw_consul_idx, CONSUL_LOCK_KEY)
                            raise SetupError(status, 'Admin user creation failed on'
                                f' "{Rgw._machine_id}" node, with all data pods - {data_pod_hostnames}')

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
        log_dir = conf.get(LOG_PATH_KEY)
        log_file_path = os.path.join(log_dir, COMPONENT_NAME, Rgw._machine_id)
        # create radosgw logrotate file.
        # For eg:
        # filepath='/etc/logrotate.d/radosgw'
        old_file = os.path.join(LOGROTATE_DIR, 'ceph')
        if os.path.exists(old_file):
            os.remove(old_file)
        try:
            with open(LOGROTATE_TMPL, 'r') as f:
                content = f.read()
            content = content.replace('TMP_LOG_PATH', log_file_path)
            with open(LOGROTATE_CONF, 'w') as f:
                f.write(content)
            Log.info(f'{LOGROTATE_TMPL} file copied to {LOGROTATE_CONF}')
        except Exception as e:
            Log.error(f"Failed to configure logrotate for {COMPONENT_NAME}. ERROR:{e}")

    @staticmethod
    def _verify_backend_store_value(conf: MappedConf):
        """Verify backed store value as motr."""
        config_file = Rgw._get_rgw_config_path(conf)
        Rgw._load_rgw_config(Rgw._rgw_conf_idx, f'ini://{config_file}')
        backend_store = Conf.get(Rgw._rgw_conf_idx, 'client>rgw backend store')
        if not backend_store in SUPPORTED_BACKEND_STORES:
            raise SetupError(errno.EINVAL,
                f'Supported rgw backend store are {SUPPORTED_BACKEND_STORES},'
                f' currently configured one is {backend_store}')
