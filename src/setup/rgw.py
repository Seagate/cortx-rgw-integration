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
from cortx.utils.validator.v_pkg import PkgV
from cortx.utils.conf_store import Conf, MappedConf
from cortx.utils.conf_store.error import ConfError
from cortx.utils.process import SimpleProcess
from cortx.utils.log import Log
from src.setup.error import SetupError
from src.const import (
    CORTX_RPMS, CEPH_RPMS, RGW_CONF_TMPL, RGW_CONF_FILE, CONFIG_PATH_KEY)


class Rgw:
    """Represents RGW and Performs setup related actions."""

    _machine_id = Conf.machine_id
    _rgw_conf_idx = 'rgw_config'

    @staticmethod
    def validate(phase: str):
        """Perform validations."""

        Log.info(f'validations started for {phase} phase.')

        if phase == 'post_install':
            # Perform RPM validations
            for rpms in [CORTX_RPMS, CEPH_RPMS]:
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
            rgw_tmpl_idx = 'rgw_conf_tmpl'
            rgw_tmpl_url = f'ini://{RGW_CONF_TMPL}'
            Rgw._load_rgw_config(rgw_tmpl_idx, rgw_tmpl_url)
            Rgw._load_rgw_config(Rgw._rgw_conf_idx, f'ini://{rgw_config_path}')
            Conf.copy(rgw_tmpl_idx, Rgw._rgw_conf_idx)
            Conf.save(Rgw._rgw_conf_idx)
            Log.info(f'{RGW_CONF_TMPL} config copied to {rgw_config_path}.')

        except Exception as e:
            raise SetupError(errno.EINVAL, f'Error ocurred while fetching node ip, {e}')

        Log.info('Prepare phase completed.')

        return 0

    @staticmethod
    def config(conf: MappedConf):
        """Performs configurations."""

        Log.info('Config phase started.')

        Log.info('create symbolic link of FID config files started')
        Rgw._create_symbolic_link_fid(conf)
        Log.info('create symbolic link of FID config files completed')
        Log.info('fetching endpoint values from hare sysconfig file.')
        # for running radosgw-admin tool, we are using endpoints mentioned
        # in first symlink file 'rgw-1' as a default endpoint vlaues.
        rgw_service_endpoints = Rgw._parse_endpoint_values(conf, 'rgw-1')
        Log.info('updating endpoint values in rgw config file.')
        Rgw._update_rgw_config_with_endpoints(conf, rgw_service_endpoints)

        Log.info('Config phase completed.')
        return 0

    @staticmethod
    def init(conf: MappedConf):
        """Perform initialization."""

        Log.info('Init phase started.')
        # TODO: Create admin user.
        # admin user should be created only on one node.
        # 1. While creating admin user, global lock created in consul kv store.
        # (rgw_consul_index, cortx>rgw>volatile>rgw_lock, machine_id)
        # 2. Before creating admin user.
        #    a. Check for rgw_lock in consul kv store.
        #    b. Create user only if lock value is None/machine-id.

        rgw_lock = False
        rgw_lock_key = 'component>rgw>volatile>rgw_lock'
        rgw_consul_idx = 'rgw_consul_idx'
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

        endpoints = conf.get('cortx>external>consul>endpoints')
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
            Conf.load(conf_idx, conf_url, skip_reload=True)
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
        config_path = conf.get(CONFIG_PATH_KEY)
        rgw_config_dir = os.path.join(config_path, 'rgw', Rgw._machine_id)
        return rgw_config_dir

    @staticmethod
    def _create_rgw_user(conf):
        """Create RGW admin user."""
        user_name = conf.get('cortx>rgw>auth_user')
        access_key = conf.get('cortx>rgw>auth_admin')
        auth_secret = conf.get('cortx>rgw>auth_secret')
        err_str = f'user: {user_name} exists'
        rgw_config = Rgw._get_rgw_config_path(conf)
        create_usr_cmd = f'sudo radosgw-admin user create --uid={user_name} --access-key \
            {access_key} --secret {auth_secret} --display-name="{user_name}" -c {rgw_config} --no-mon-config'
        _, err, rc, = SimpleProcess(create_usr_cmd).run()
        if rc == 0:
            Log.info(f'RGW admin user {user_name} is created.')
        elif rc != 0:
            if err and err_str in err.decode():
                Log.info(f'RGW admin user {user_name} is already created. skipping user creation.')
            else:
                raise SetupError(rc, f'"{create_usr_cmd}" failed with error {err}.')

    @staticmethod
    def _create_symbolic_link_fid(conf: MappedConf):
        """ Create symbolic link of FID sysconfig files."""
        base_config_path = conf.get(CONFIG_PATH_KEY)
        sysconfig_file_path = os.path.join(base_config_path, 'rgw', 'sysconfig', Rgw._machine_id)
        file_name = sysconfig_file_path + '/rgw-0x*'
        list_matching = []
        for name in glob.glob(file_name):
            list_matching.append(name)
        count = len(list_matching)
        Log.info(f'rgw FID file count : {count}')
        if count < 1:
           raise Exception(f'HARE-sysconfig file is missing at {sysconfig_file_path}')

        # Create symbolic links of rgw-fid files created by hare.
        # e.g rgw-0x7200000000000001\:0x9c -> rgw-1 , rgw-0x7200000000000001\:0x5b -> rgw-2
        index = 1
        for src_path in list_matching:
            file_name = 'rgw-' + str(index)
            dst_path = os.path.join(sysconfig_file_path, file_name)
            Rgw._create_symbolic_link(src_path, dst_path)
            index += 1

    @staticmethod
    def _create_symbolic_link(src_path: str, dst_path: str):
        """create symbolic link."""
        Log.info(f'symbolic link source path: {src_path}')
        Log.info(f'symbolic link destination path: {dst_path}')
        if os.path.exists(dst_path):
           Log.info('symbolic link is already present')
           os.unlink(dst_path)
           Log.info('symbolic link is unlinked')
        os.symlink(src_path, dst_path)
        Log.info(f'symbolic link created successfully')

    @staticmethod
    def _parse_endpoint_values(conf, rgw_instance_name: str):
        """Read sysconfig file generated by hare
         1) Read symblink file '{rgw_instance_name}' as default endpoints in config phase.
         2) fetch endpoint values for running radosgw-admin tool.
        """
        base_config_path = conf.get(CONFIG_PATH_KEY)
        sysconfig_file_path = os.path.join(base_config_path, 'rgw', 'sysconfig', Rgw._machine_id)
        endpoint_file = os.path.join(sysconfig_file_path, rgw_instance_name)
        endpoints = {}
        with open(endpoint_file) as ep_file:
            for line in ep_file:
                ep_name, ep_value = line.partition('=')[::2]
                endpoints[ep_name.strip()] = str(ep_value.strip())

        return endpoints

    @staticmethod
    def _update_rgw_config_with_endpoints(conf, endpoints: dict):
        """Update endpoint values to rgw config file."""
        rgw_config_dir = Rgw._get_rgw_config_dir(conf)
        rgw_config_file = os.path.join(rgw_config_dir, RGW_CONF_FILE)
        Rgw._load_rgw_config(Rgw._rgw_conf_idx, f'ini://{rgw_config_file}')
        Conf.set(Rgw._rgw_conf_idx, 'client>motr profile fid', endpoints['MOTR_PROFILE_FID'])
        Conf.set(Rgw._rgw_conf_idx, 'client>motr ha endpoint', endpoints['MOTR_HA_EP'])
        Conf.set(Rgw._rgw_conf_idx, 'client>motr my endpoint', endpoints['MOTR_RGW_EP'])
        Conf.set(Rgw._rgw_conf_idx, 'client>motr my fid', endpoints['MOTR_PROCESS_FID'])
        Conf.set(Rgw._rgw_conf_idx, 'client>admin motr fid', endpoints['MOTR_PROCESS_FID'])
        Conf.set(Rgw._rgw_conf_idx, 'client>admin motr endpoint', endpoints['MOTR_RGW_EP'])
        Conf.save(Rgw._rgw_conf_idx)
