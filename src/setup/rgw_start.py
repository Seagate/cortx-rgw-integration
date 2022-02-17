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
from cortx.utils.log import Log
from src.setup.error import SetupError
from cortx.utils.conf_store import MappedConf


class RgwStart:
    """Entrypoint class for RGW."""

    @staticmethod
    def start_rgw(conf: MappedConf, config_file, log_file, index: str = '1',):
        """Start rgw service independently."""
        Log.info("Starting radosgw service.")
        try:
            # TODO: To replace os.system with SimpleProcess calls
            os.system(f"sh /opt/seagate/cortx/rgw/bin/rgw_service -i {index} -c {config_file} -l {log_file}")
        except OSError as e:
            Log.error(f"Failed to start radosgw service:{e}")
            raise SetupError(e.errno, "Failed to start radosgw service. %s", e)
        Log.info("Started radosgw service.")
