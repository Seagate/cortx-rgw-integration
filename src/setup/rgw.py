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
import shutil
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
            # Copy cortx_rgw to <config> dir.
            # TODO: Use Conf.copy() api once the
            # https://github.com/Seagate/cortx-utils/pull/728 PR is merge.

            # rgw_tmpl_idx = 'rgw_conf_tmpl'
            # rgw_tmpl_url = f'ini://{RGW_CONF_TMPL}'
            # Rgw._load_rgw_config(rgw_tmpl_idx, rgw_tmpl_url)
            # RGW._load_rgw_config(RGW._rgw_conf_idx, f'ini://{rgw_conf_file_path}')
            # Conf.copy(rgw_tmpl_idx, RGW._rgw_conf_idx)
            shutil.copyfile(RGW_CONF_TMPL, rgw_config_path)
            Log.info(f'{RGW_CONF_TMPL} config copied to {rgw_config_path}.')

        except Exception as e:
            raise SetupError(errno.EINVAL, f'Error ocurred while fetching node ip, {e}')

        Log.info('Prepare phase completed.')

        return 0

    @staticmethod
    def config(conf: MappedConf):
        """Performs configurations."""

        Log.info('Config phase started.')

        # TODO: Inside [client.rgw.<hostname>] section and
        # add motr,hax endpoints and rgw client related parameters.
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
                    Conf.set(rgw_consul_idx, rgw_lock_key,rgw_lock_val)
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
            # TODO: Add rgw admin user creation.
            # Before creating user check if user is already created.
            # If user is present in user list then skip the user creation.
            # RGW._create_rgw_user(conf)
            Log.info('User is created.')
            Log.info(f'Deleting rgw_lock key {rgw_lock_key}.')
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
        config_path = conf.get(CONFIG_PATH_KEY)
        rgw_config_dir = os.path.join(config_path, 'rgw', Rgw._machine_id)
        os.makedirs(rgw_config_dir, exist_ok=True)
        rgw_conf_file_path = os.path.join(rgw_config_dir, RGW_CONF_FILE)
        return rgw_conf_file_path

    @staticmethod
    def _create_rgw_user(conf):
        """Create RGW admin user."""
        user_name = conf.get('cortx>rgw>auth_user')
        access_key = conf.get('cortx>rgw>auth_admin')
        auth_secret = conf.get('cortx>rgw>auth_secret')
        rgw_config = Rgw._get_rgw_config_path(conf)
        create_usr_cmd = f'sudo radosgw-admin user create --uid={user_name} --access-key \
            {access_key} --secret {auth_secret} --display-name="{user_name}" -c {rgw_config}'
        check_user_cmd = f'radosgw-admin user info --uid {user_name} --no-mon-config -c {rgw_config}'
        _, _, rc, = SimpleProcess(check_user_cmd).run()
        if rc == 0:
            Log.info(f'RGW adin user {user_name} is already created, skipping user creation.')
            return 0
        _, err, rc, = SimpleProcess(create_usr_cmd).run()
        if rc != 0:
            raise SetupError(rc, f'"{create_usr_cmd}" failed with error {err}.')
