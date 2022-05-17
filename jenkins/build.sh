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
MOTR_TMP_CODE="$BASE_DIR/../motr_code"
MOTR_URL="https://github.com/Seagate/cortx-motr.git"
ADDB_PLUGIN_DIR="$BASE_DIR"/src/addb_plugin

usage() {
    echo """usage: $PROG [-v version] [-g git_version] [-b build_number]""" 1>&2;
    exit 1;
}

build_addb_plugin(branch_name="main") {
    echo """build addb plugin and bundle this binary file as a part of cortx-rgw-integration rpm.
     1. Clone motr code
     2. generate addb plugin
     3. add binary to rpm
    """
    mkdir -p "$MOTR_TMP_CODE"
    cd "$MOTR_TMP_CODE"
    git clone $MOTR_URL -b $branch_name
    cd -

    echo "building addb plugin"
    cd "$ADDB_PLUGIN_DIR"
    make plugin || { echo "Failed to build addb plugin hence skipping addb steps !!!"}

    rm -r "$MOTR_TMP_CODE"
    cd -
    echo "Done with building addb librabry plugin."
}

# Check for passed in arguments
while getopts ":g:v:b:" o; do
    case "${o}" in
        v)
            VER=${OPTARG}
            ;;
        g)
            GIT_VER=${OPTARG}
            ;;
        b)
            BUILD_NUMBER=${OPTARG}
            ;;
        *)
            usage
            ;;
    esac
done

[ -z $"$GIT_VER" ] && GIT_VER="$(git rev-parse --short HEAD)" \
        || GIT_VER="${GIT_VER}_$(git rev-parse --short HEAD)"
[ -z "$VER" ] && VER="2.0.0"
[ -z "$BUILD_NUMBER" ] && BUILD_NUMBER=1
REL="${BUILD_NUMBER}_${GIT_VER}"

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

echo "Generating addb plugin"
required_addb_rpms={make, gcc}
build_addb=true
for pkg in required_addb_rpms:
  rpm -q $pkg > /dev/null || {
    echo "Required rpm : $pkg for addb is not installed.Hence skipping addb plugin build process !!!"
    build_addb=false
  }

# if requried rpms are not present then skip addb build process.
if build_addb:
   build_addb_plugin

echo "Creating cortx-rgw-integration RPM with version $VER, release $REL"

# Building rpm using setuptool utility
cd "$BASE_DIR"

requirements=$(sed -z 's/\n/,/g' requirements.txt | sed -e 's/,$//')

/usr/bin/python3.6 setup.py bdist_rpm --release="$REL" --requires "$requirements"

if [ $? -ne 0 ]; then
  echo "ERROR !!! cortx-rgw-integration rpm build failed !!!"
  exit 1
else
  echo "cortx-rgw-integration rpm build successful !!!"
fi

