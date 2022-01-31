#!/usr/bin/python3

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

import sys
import errno
import traceback

from cortx.utils.log import Log
from cortx.utils.cmd_framework import Cmd
from setup import Rgw
from error import SetupError

class SetupCmdBase(Cmd):
    """Setup cmd base class."""

    def __init__(self, *args):
        """Initialize super class members."""
        super().__init__(*args)

    def add_args(parser):
        parser.add_argument('--services', default='services', help='services')
        parser.add_argument('--config', default='config_url', help='config')

class PostInstallCmd(SetupCmdBase):
    """PostInstall Setup Cmd."""

    name = 'post_install'

    def __init__(self, args: dict):
        """Initialize super class members."""
        super().__init__(args)

    def process(self):
        Rgw.validate('post_install')
        rc = Rgw.post_install(self._url)
        return rc


class PrepareCmd(SetupCmdBase):
    """Prepare Setup Cmd."""
    name = 'prepare'

    def __init__(self, args: dict):
        """Initialize super class members."""
        super().__init__(args)

    def process(self):
        Rgw.validate('prepare')
        rc = Rgw.prepare(self._url)
        return rc


class ConfigCmd(SetupCmdBase):
    """Setup Config Cmd."""
    name = 'config'

    def __init__(self, args):
        """Initialize super class members."""
        super().__init__(args)

    def process(self):
        Rgw.validate('config')
        rc = Rgw.config(self._url)
        return rc


class InitCmd(SetupCmdBase):
    """Init Setup Cmd."""
    name = 'init'

    def __init__(self, args):
        """Initialize super class members."""
        super().__init__(args)
        self.config_path = args.config

    def process(self):
        Rgw.validate('init')
        rc = Rgw.init(self.config_path)
        return rc


class TestCmd(SetupCmdBase):
    """Test Setup Cmd."""
    name = 'test'

    def __init__(self, args):
        """Initialize super class members."""
        super().__init__(args)
        self.config_path = args.config
        # Default test_plan is 'sanity'
        self.test_plan = args.plan

    def process(self):
        Rgw.validate('test')
        rc = Rgw.test(self.config_path, self.test_plan)
        return rc


class ResetCmd(SetupCmdBase):
    """Reset Setup Cmd."""
    name = 'reset'

    def __init__(self, args):
        """ Initialize super class members."""
        super().__init__(args)
        self.config_path = args.config

    def process(self):
        Rgw.validate('reset')
        rc = Rgw.reset(self.config_path)
        return rc


class CleanupCmd(SetupCmdBase):
    """Cleanup Setup Cmd."""
    name = 'cleanup'

    def __init__(self, args: dict):
        """Initialize super class members."""
        super().__init__(args)
        self.config_path = args.config

    def process(self):
        Rgw.validate('cleanup')
        rc = Rgw.cleanup(self.config_path)
        return rc


class UpgradeCmd(SetupCmdBase):
    """Upgrade Setup Cmd."""
    name = 'upgrade'

    def __init__(self, args: dict):
        """Initialize super class members."""
        super().__init__(args)
        self.config_path = args.config

    def process(self):
        Rgw.validate('upgrade')
        rc = Rgw.upgrade(self.config_path)
        return rc


def main():
    argv = sys.argv

    Log.init() # TODO

    try:
        desc = "CORTX Rgw Setup command"
        command = Cmd.get_command(desc, argv[1:])
        rc = command.process()

    except SetupError as e:
        sys.stderr.write("error: %s\n\n" % str(e))
        sys.stderr.write("%s\n" % traceback.format_exc())
        Cmd.usage(argv[0])
        rc = e.rc

    except Exception as e:
        sys.stderr.write("error: %s\n\n" % str(e))
        sys.stderr.write("%s\n" % traceback.format_exc())
        rc = errno.EINVAL

    Log.info(f"Command {command} {argv[1]} completed with rc:{rc}")

if __name__ == '__main__':
    sys.exit(main())
