#!/bin/bash
#
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

set -e

PROG=$(basename "$0")
SCRIPT_DIR=$(realpath $(dirname "$0"))
BASE_DIR="$SCRIPT_DIR"/..
BUILD_NUMBER=
GIT_VER=
PRODUCT="cortx"
ADDB_PLUGIN_DIR="$BASE_DIR"/src/addb_plugin
MOTR_REPO="$BASE_DIR"/../cortx-motr
RGW_REPO="$BASE_DIR"/../cortx-rgw

usage() {
    echo "usage: sh $PROG [--v|--version <version-id>] [--g|git_hash <git_version>] [--b|--build_no <build_number>] [--addb|--build_addb] [--h|--help]
    where,
        --v|--version <version_id>    Specify rpm version
        --g|--git_hash <git_version>  Specify git version hash
        --b|--build_no <build_number> Specify build version
        --addb|--build_addb           Generates addb plugin as part of cortx-rgw-integration
        --h|--help                    Shows script usage " 1>&2;
    exit 1;
}

build_addb_plugin() {
    # Check if required packages are installed.
    required_addb_rpms=("make" "gcc")
    for pkg in "$required_addb_rpms"
    do
      rpm -q "$pkg" > /dev/null || {
        echo "ERROR::required rpm : $pkg for building addb plugin is not installed !!!"
        exit 1;
      }
    done

    # check if cortx-motr & cortx-rgw repo are available
    for repo in $RGW_REPO $MOTR_REPO
    do
      if [ ! -d "$repo" ]; then
        echo "ERROR:: Required repository is missing for building addb plugin : $repo !!!"
        exit 1;
      fi
    done

    echo "Generating addb plugin at $ADDB_PLUGIN_DIR"
    cd "$ADDB_PLUGIN_DIR"
    make plugin
    if [ $? -ne 0 ]; then
      echo "ERROR !!! Failed to build addb plugin !!!"
      cd -
      exit 1;
    else
      cd -
      echo "Done with building addb plugin !!!"
    fi
}


# Check for passed in arguments
while [ $# -gt 0 ]; do
    case "$1" in
        --v|--version)
            shift 1
            VER=$1
            ;;
        --g|--git_hash)
            shift 1
            GIT_VER=$1
            ;;
        --b|--build_no)
            shift 1
            BUILD_NUMBER=$1
            ;;
        --addb|--build_addb)
            BUILD_ADDB=true  # if flag is set addb pluign will be generated
            ;;
        --h|--help)
            usage
            ;;
        *)
            echo "Invalid argument provided : $1"
            usage
            ;;
    esac
    shift 1
done

[ -z $"$GIT_VER" ] && GIT_VER="$(git rev-parse --short HEAD)" \
        || GIT_VER="${GIT_VER}_$(git rev-parse --short HEAD)"
[ -z "$VER" ] && VER="2.0.0"
[ -z "$BUILD_NUMBER" ] && BUILD_NUMBER=1
REL="${BUILD_NUMBER}_${GIT_VER}"
[ -z "$BUILD_ADDB" ] && BUILD_ADDB="false"

rpm -q rpm-build > /dev/null || {
    echo "error: rpm-build is not installed. Install rpm-build and run $PROG"
    exit 1;
}

# Create version file
echo $VER > "$BASE_DIR"/VERSION
/bin/chmod +rx "$BASE_DIR"/VERSION
/bin/chmod +x "$BASE_DIR"/src/rgw/setup/rgw_setup
/bin/chmod +x "$BASE_DIR"/src/rgw/setup/rgw_service.py
/bin/chmod +x "$BASE_DIR"/src/rgw/support/rgw_support_bundle

INSTALL_PATH="/opt/seagate/""${PRODUCT}"

mkdir -p "$INSTALL_PATH"

# build addb plugin
if [ "$BUILD_ADDB" == "true" ]; then
  echo "Building addb plugin(rgw_addb_plugin.so) for RGW and bundling same
in cortx-rgw-integration rpm"
  build_addb_plugin
fi

echo "Creating cortx-rgw-integration RPM with version $VER, release $REL"

# Building rpm using setuptool utility
cd "$BASE_DIR"

requirements=$(sed -z 's/\n/,/g' requirements.txt | sed -e 's/,$//')

/usr/bin/python3.6 setup.py bdist_rpm --release="$REL" --requires "$requirements" --force-arch=x86_64

if [ $? -ne 0 ]; then
  echo "ERROR !!! cortx-rgw-integration rpm build failed !!!"
  exit 1
else
  echo "cortx-rgw-integration rpm build successful !!!"
fi
