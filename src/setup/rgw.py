#! /usr/bin/python3

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


class Rgw:
    """ Represents Utils and Performs setup related actions """

    @staticmethod
    def validate(phase: str):
        """ Perform validtions """

        # Perform RPM validations
        return 0

    @staticmethod
    def post_install(config_path: str):
        """ Performs post install operations """

        return 0

    @staticmethod
    def config(config_path: str):
        """Performs configurations."""

        return 0

    @staticmethod
    def init(config_path: str):
        """ Perform initialization """

        return 0

    @staticmethod
    def test(config_path: str, plan: str):
        """ Perform configuration testing """

        return 0

    @staticmethod
    def reset(config_path: str):
        """Remove/Delete all the data/logs that was created by user/testing."""

        return 0

    @staticmethod
    def cleanup(pre_factory: bool, config_path: str):
        """Remove/Delete all the data that was created after post install."""

        return 0

    @staticmethod
    def upgrade(config_path: str):
        """Perform upgrade steps."""

        return 0
