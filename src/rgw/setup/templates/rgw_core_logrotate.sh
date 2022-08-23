#!/bin/sh
#
# Copyright (c) 2022 Seagate Technology LLC and/or its Affiliates
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# For any questions about this software or licensing,
# please email opensource@seagate.com or cortx-questions@seagate.com.
#

# script is used to delete the old rgw core files in /etc/cortx/log/rgw/<machine-id>/rgw_debug directory
# script will retain latest 5 core file and remove rest of core files.
# argument1: <number of latest rgw core files to retain>
# Default number of latest log files is 2
# ./rgw_core_logrotate.sh -n 2

usage() { echo "Usage: bash $(basename "$0")[--help|-h]
                   [-n maxRgwCoreFileCount]
Retain recent generated rgw core files of given count and remove rest of core files.

where:
-n            number of latest rgw core files to retain (Default count for core files is 2)
--help|-h     display this help and exit" 1>&2; exit 1; }

# max rgw core files count in each rgw log directory
core_files_max_count=2
rgw_core_dir="TEMP_CORE_FILE_DIR_PATH"

while getopts ":n:" option; do
    case "${option}" in
        n)
            core_files_max_count=${OPTARG}
            if [ -z "${core_files_max_count}" ]
            then
              usage
            fi
            ;;
        *)
            usage
            ;;
    esac
done

echo "max RGW core file to be preserved: $core_files_max_count"
echo

echo "Checking for core files in $rgw_core_dir directory"
if [[ -n "$rgw_core_dir" && -d "$rgw_core_dir" ]]
then
    # Find core files
     core_files=$(find "$rgw_core_dir" -maxdepth 1 -type f -name "core.*")
     core_files_count=$(echo "$core_files" | grep -v "^$" | wc -l)
     echo "## found $core_files_count file(s) in log directory($rgw_core_dir) ##"
     # check core files count is greater than max core file count or not
     if [ "$core_files_count" -gt "$core_files_max_count" ]
     then
        # get files sort by date - oldest will come on top
        remove_file_count=$(("$core_files_count"-"$core_files_max_count"))
        if [ "$remove_file_count" -gt 0 ]
        then
            echo "## ($remove_file_count) rgw core file(s) can be removed from directory :$rgw_core_dir ##"
            # get the files sorted by time modified (most recently modified comes last),
            # that is oldest files will come on top.
            files_to_remove=$(ls -tr "$rgw_core_dir" | grep core | head -n "$remove_file_count")
            for file in $files_to_remove
            do
              rm -f "$rgw_core_dir/$file"
            done
            echo "## deleted ($remove_file_count) core file(s) from directory: $rgw_core_dir ##"
        fi
     fi
else
    echo "ERROR !!! Invalid directory path : $rgw_core_dir. Please add proper path of rgw core directory."
    exit
fi

echo "Done with rgw core file rotation"
