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
from cortx.utils.validator.v_pkg import PkgV
from cortx.utils.conf_store import Conf, MappedConf
from cortx.utils.conf_store.error import ConfError
from cortx.utils.process import SimpleProcess
from cortx.utils.log import Log
from src.setup.error import RgwSetupError
from src.setup.const import (
    cortx_rpms, ceph_rpms, ceph_conf_tmpl_file, ceph_conf_tmpl_url,
    ceph_conf_file, ceph_conf_path, ceph_admin_keyring_file)


class Rgw:
    """Represents RGW and Performs setup related actions."""

    _machine_id = Conf.machine_id

    @staticmethod
    def validate(phase: str):
        """Perform validations."""

        Log.info(f'validations started for {phase} phase.')

        if phase == "post_install":
            # Perform RPM validations
            for rpms in [cortx_rpms, ceph_rpms]:
                PkgV().validate('rpms', rpms)
            Log.info(f'All required rpms are installed on {Rgw._machine_id} node.')
        elif phase == "prepare":
            Rgw._file_exist(ceph_conf_tmpl_file)
        elif phase == 'config':
            Rgw._file_exist(ceph_conf_file)

        Log.info(f'validations completed for {phase} phase.')

        return 0

    @staticmethod
    def post_install(cortx_gconf: MappedConf):
        """Performs post install operations."""

        Log.info('PostInstall phase completed.')
        return 0

    @staticmethod
    def prepare(cortx_gconf: MappedConf):
        """Perform prepare operations."""

        Log.info('Prepare phase started.')

        try:
            hostname = cortx_gconf.get(f'node>{Rgw._machine_id}>hostname')
            host_ip = socket.gethostbyname(hostname)
            ceph_tmpl_idx = 'ceph_conf_tmpl'
            # Load template ceph.conf file and updated required field.
            kv_list = [
                ('global>fsid', str(uuid.uuid1())),
                ('global>mon host', host_ip)]
            Rgw._update_config(ceph_tmpl_idx, kv_list, ceph_conf_tmpl_url)

            # Copy ceph_conf_tmpl_file to /etc/ceph/ dir.
            if not os.path.exists(ceph_conf_path):
                os.mkdir(ceph_conf_path)
            shutil.copyfile(ceph_conf_tmpl_file, ceph_conf_file)
            Log.info(f'{ceph_conf_tmpl_file} config copied to {ceph_conf_file}.')

            # create admin keyring.
            cmd = f"sudo ceph-authtool --create-keyring {ceph_admin_keyring_file} \
                --gen-key -n client.admin --cap mon 'allow *' --cap osd 'allow *'"
            _, err, rc, = SimpleProcess(cmd).run()
            if rc != 0:
                raise RgwSetupError(errno.EINVAL, '"{cmd}" failed with error {err}.')
        except Exception as e:
            raise RgwSetupError(errno.EINVAL, f'Error ocurred while fetching node ip, {e}')

        Log.info('Prepare phase completed.')

        return 0

    @staticmethod
    def config(cortx_gconf: MappedConf):
        """Performs configurations."""

        Log.info('Config phase started.')

        # TODO: Inside [client.rgw.<hostname>] section and
        # add motr,hax endpoints and rgw client related parameters.
        Log.info('Config phase completed.')
        return 0

    @staticmethod
    def init(cortx_gconf: MappedConf):
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
        consul_url = Rgw._get_consul_url(cortx_gconf)
        # Check for rgw_lock in consul kv store.
        Log.info('Checking for rgw lock in consul kv store.')
        Conf.load(rgw_consul_idx, consul_url)

        while(True):
            try:
                rgw_lock_val = Conf.get(rgw_consul_idx, rgw_lock_key)
                Log.info(f'rgw_lock value - {rgw_lock_val}')
                if rgw_lock_val is None:
                    Log.info(f'Setting confstore value for key :{rgw_lock_key}'
                        f' and value as :{Rgw._machine_id}')
                    Rgw._update_config(rgw_consul_idx, [(rgw_lock_key, Rgw._machine_id)])
                    Log.info('Updated confstore with latest value')
                    time.sleep(3)
                    continue
                elif rgw_lock_val == Rgw._machine_id:
                    Log.info('Found lock acquired successfully hence processing'
                        ' with openldap schema push')
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
    def test(cortx_gconf: MappedConf, plan: str):
        """Perform configuration testing."""

        Log.info('Test phase completed.')
        return 0

    @staticmethod
    def reset(cortx_gconf: MappedConf):
        """Remove/Delete all the data/logs that was created by user/testing."""

        Log.info('Reset phase completed.')
        return 0

    @staticmethod
    def cleanup(cortx_gconf: MappedConf, pre_factory: bool):
        """Remove/Delete all the data that was created after post install."""

        Log.info('Cleanup phase completed.')
        return 0

    @staticmethod
    def upgrade(cortx_gconf: MappedConf):
        """Perform upgrade steps."""

        Log.info('Upgrade phase completed.')
        return 0

    @staticmethod
    def _get_consul_url(cortx_gconf: MappedConf):
        """Return consul url."""

        cortx_consul_endpoint_key = 'cortx>external>consul>endpoints'
        consul_endpoint_list = cortx_gconf.get(cortx_consul_endpoint_key)
        consul_fqdn = None
        for endpoint in consul_endpoint_list:
            if 'http' in endpoint:
                consul_fqdn = endpoint.split('http')[1]
                break
        consul_url = 'consul' + consul_fqdn
        return consul_url

    @staticmethod
    def _file_exist(file_path: str):
        """Return True if given file exist else False."""
        exist = True
        if not os.path.exists(file_path):
            exist = False
            raise RgwSetupError(errno.EINVAL,
                f'{file_path} file not exists.')
        return exist

    @staticmethod
    def _update_config(conf_idx: str, kv_list: list, conf_url: str = None):
        """Add/Updated key-values in given config."""
        try:
            if conf_url is not None:
                Conf.load(conf_idx, conf_url, skip_reload=True)
            for key, val in kv_list:
                Conf.set(conf_idx, key, val)
            Conf.save(conf_idx)
        except (AssertionError, ConfError) as e:
            raise RgwSetupError(errno.EINVAL,
                f'Error occurred while adding the key in {conf_url} config. {e}')
