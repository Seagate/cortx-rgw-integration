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
import sys

from cortx.utils.log import Log
from cortx.rgw.setup.error import SetupError
from cortx.utils.conf_store import MappedConf
from cortx.rgw.const import INSTALL_PATH, COMPONENT_NAME


class RgwService:
    """Entrypoint class for RGW."""

    @staticmethod
    def start(conf: MappedConf, config_file, log_file, motr_trace_dir, rgw_crash_dir, index: str = '1',):
        """Start rgw service independently."""
        try:
            os.environ['M0_TRACE_DIR'] = motr_trace_dir
            cmd = os.path.join(INSTALL_PATH, COMPONENT_NAME, 'bin/radosgw_start')
            sys.stdout.flush()
            sys.stderr.flush()
            os.execl(cmd, cmd, index, config_file, log_file, rgw_crash_dir)
        except OSError as e:
            Log.error(f"Failed to start radosgw service:{e}")
            raise SetupError(e.errno, "Failed to start radosgw service. %s", e)
        except Exception as e:
            Log.error(f"Failed to start radosgw service:{e}")
            raise SetupError(e, "Failed to start radosgw service. %s", e)