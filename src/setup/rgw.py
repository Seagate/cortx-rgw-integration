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
import uuid
import errno
import shutil
import socket
from urllib.parse import urlparse
from cortx.utils.validator.v_pkg import PkgV
from cortx.utils.conf_store import Conf, MappedConf
from cortx.utils.conf_store.error import ConfError
from cortx.utils.process import SimpleProcess
from cortx.utils.log import Log
from src.setup.error import SetupError
from src.const import (
    CORTX_RPMS, CEPH_RPMS, CEPH_CONF_TMPL, CEPH_CONF, CEPH_ADMIN_KEYRING)


class Rgw:
    """Represents RGW and Performs setup related actions."""

    _machine_id = Conf.machine_id

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
            Rgw._file_exist(CEPH_CONF_TMPL)
        elif phase == 'config':
            Rgw._file_exist(CEPH_CONF)

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
            hostname = conf.get(f'node>{Rgw._machine_id}>hostname')
            host_ip = socket.gethostbyname(hostname)
            ceph_tmpl_idx = 'ceph_conf_tmpl'
            ceph_tmpl_url = f'ini://{CEPH_CONF_TMPL}'
            # Load template ceph.conf file and update required field.
            kv_list = [
                ('global>fsid', str(uuid.uuid1())),
                ('global>mon host', host_ip)]
            Rgw._update_config(ceph_tmpl_idx, ceph_tmpl_url, kv_list)

            # Copy ceph_conf_tmpl_file to /etc/ceph/ dir.
            shutil.copyfile(CEPH_CONF_TMPL, CEPH_CONF)
            Log.info(f'{CEPH_CONF_TMPL} config copied to {CEPH_CONF}.')

            # create admin keyring.
            cmd = f"sudo ceph-authtool --create-keyring {CEPH_ADMIN_KEYRING} \
                --gen-key -n client.admin --cap mon 'allow *' --cap osd 'allow *'"
            _, err, rc, = SimpleProcess(cmd).run()
            if rc != 0:
                raise SetupError(errno.EINVAL, f'"{cmd}" failed with error {err}.')
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

        while(True):
            try:
                rgw_lock_val = Conf.get(rgw_consul_idx, rgw_lock_key)
                Log.info(f'rgw_lock value - {rgw_lock_val}')
                # TODO: Explore consul lock - https://www.consul.io/commands/lock
                if rgw_lock_val is None:
                    Log.info(f'Setting confstore value for key :{rgw_lock_key}'
                        f' and value as :{Rgw._machine_id}')
                    Rgw._update_config(
                        rgw_consul_idx, consul_url, [(rgw_lock_key, Rgw._machine_id)])
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
                        ' acquired by {rgw_lock_val}')
                    rgw_lock = False
                    break

            except Exception as e:
                Log.error('Exception occured while connecting to consul service'
                    f' endpoint {e}')
                break
        if rgw_lock is True:
            Log.info('Creating admin user.')
            # TODO: Add rgw admin user creation.
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
        if os.path.exists(CEPH_CONF):
            os.remove(CEPH_CONF)
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
        # Relace 'http' with 'consul' in endpoint string.
        consul_url = 'consul' + http_endpoints[seq].split('http')[1]
        return consul_url

    @staticmethod
    def _file_exist(file_path: str):
        """Check if a file is exists."""
        if not os.path.exists(file_path):
            raise SetupError(errno.EINVAL,
                f'{file_path} file not exists.')

    @staticmethod
    def _update_config(conf_idx: str, conf_url: str, kv_list: list):
        """Add/Updated key-values in given config."""
        try:
            if conf_url is None:
                raise SetupError(errno.EINVAL, 'Conf url is None.')
            Conf.load(conf_idx, conf_url, skip_reload=True)
            for key, val in kv_list:
                Conf.set(conf_idx, key, val)
            Conf.save(conf_idx)
        except (AssertionError, ConfError) as e:
            raise SetupError(errno.EINVAL,
                f'Error occurred while adding the key in {conf_url} config. {e}')
