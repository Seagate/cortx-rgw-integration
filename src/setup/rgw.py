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
from urllib.parse import urlparse
from cortx.utils.security.certificate import Certificate
from cortx.utils.errors import SSLCertificateError
from cortx.utils.validator.v_pkg import PkgV
from cortx.utils.conf_store import Conf, MappedConf
from cortx.utils.conf_store.error import ConfError
from cortx.utils.process import SimpleProcess
from cortx.utils.log import Log
from cortx.utils.security.cipher import Cipher, CipherInvalidToken
from src.setup.error import SetupError
from src.setup.rgw_start import RgwStart
from src.const import (
    REQUIRED_RPMS, RGW_CONF_TMPL, RGW_CONF_FILE, CONFIG_PATH_KEY,
    CLIENT_INSTANCE_NAME_KEY, CLIENT_INSTANCE_NUMBER_KEY, CONSUL_ENDPOINT_KEY,
    COMPONENT_NAME, ADMIN_PARAMETERS, LOG_PATH_KEY, DECRYPTION_KEY,
    SSL_CERT_CONFIGS, SSL_DNS_LIST, RgwEndpoint)


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

        Log.info('Config phase completed.')
        return 0

    @staticmethod
    def start(conf: MappedConf, index: str):
        """Create rgw admin user and start rgw service."""

        Log.info('Create rgw admin user and start rgw service.')
        # admin user should be created only on one node.
        # 1. While creating admin user, global lock created in consul kv store.
        # (rgw_consul_index, cortx>rgw>volatile>rgw_lock, machine_id)
        # 2. Before creating admin user.
        #    a. Check for rgw_lock in consul kv store.
        #    b. Create user only if lock value is None/machine-id.

        rgw_lock = False
        rgw_lock_key = f'component>{COMPONENT_NAME}>volatile>{COMPONENT_NAME}_lock'
        rgw_consul_idx = f'{COMPONENT_NAME}_consul_idx'
        # Get consul url from cortx config.
        consul_url = Rgw._get_consul_url(conf)
        # Check for rgw_lock in consul kv store.
        Log.info('Checking for rgw lock in consul kv store.')
        Conf.load(rgw_consul_idx, consul_url)

        # if in case try-catch block code executed at the same time on all the nodes,
        # then all nodes will try to update rgw lock-key in consul, after updating key
        # it will wait for sometime(time.sleep(3)) and in next iteration all nodes will
        # get lock value as node-id of node who has updated the lock key at last.
        # and then only that node will perform the user creation operation.
        while(True):
            try:
                rgw_lock_val = Conf.get(rgw_consul_idx, rgw_lock_key)
                Log.info(f'rgw_lock value - {rgw_lock_val}')
                # TODO: Explore consul lock - https://www.consul.io/commands/lock
                if rgw_lock_val is None:
                    Log.info(f'Setting confstore value for key :{rgw_lock_key}'
                        f' and value as :{Rgw._machine_id}')
                    Rgw._load_rgw_config(rgw_consul_idx, consul_url)
                    Conf.set(rgw_consul_idx, rgw_lock_key, Rgw._machine_id)
                    Conf.save(rgw_consul_idx)
                    Log.info('Updated confstore with latest value')
                    time.sleep(3)
                    continue
                elif rgw_lock_val == Rgw._machine_id:
                    Log.info('Found lock acquired successfully hence processing'
                        ' with RGW admin user creation.')
                    rgw_lock = True
                    break
                elif rgw_lock_val != Rgw._machine_id:
                    Log.info('Skipping rgw user creation, as rgw lock is already'
                        f' acquired by {rgw_lock_val}')
                    rgw_lock = False
                    break

            except Exception as e:
                Log.error('Exception occured while connecting to consul service'
                    f' endpoint {e}')
                break
        if rgw_lock is True:
            Log.info('Creating admin user.')
            # Before creating user check if user is already created.
            Rgw._create_rgw_user(conf)
            Log.info('User is created.')
            Log.debug(f'Deleting rgw_lock key {rgw_lock_key}.')
            Conf.delete(rgw_consul_idx, rgw_lock_key)
            Log.info(f'{rgw_lock_key} key is deleted')

        # For reusing the same motr endpoint, hax needs 30 sec time to sync & release
        # for re-use by other process like radosgw here.
        time.sleep(30)
        log_path = Rgw._get_log_dir_path(conf)
        log_file = os.path.join(log_path, f'{COMPONENT_NAME}-{index}')
        config_file = Rgw._get_rgw_config_path(conf)
        RgwStart.start_rgw(conf, config_file, log_file, index)

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
        _, err, rc, = SimpleProcess(create_usr_cmd).run()
        if rc == 0:
            Log.info(f'RGW admin user {user_name} is created.')
        elif rc != 0:
            if err and err_str in err.decode():
                Log.info(f'RGW admin user {user_name} is already created. \
                    skipping user creation.')
            else:
                raise SetupError(rc, f'"{create_usr_cmd}" failed with error {err}.')

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
                log_path, COMPONENT_NAME, Rgw._machine_id, 'radosgw-admin.log')
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
            f'beast port={port} ssl_port={ssl_port} ssl_certificate={ssl_cert_path}, ssl_private_key={ssl_cert_path}')
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
