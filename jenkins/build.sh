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
BASE_DIR=$SCRIPT_DIR/..
BUILD_NUMBER=
GIT_VER=

usage() {
    echo """usage: $PROG[-v version] [-g git_version] [-b build_number]""" 1>&2;
    exit 1;
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
/bin/chmod +x "$BASE_DIR"/src/setup/rgw_setup.py

INSTALL_PATH=/opt/seagate/cortx
mkdir -p $INSTALL_PATH

# Put install_path in utils-post-install
sed -i -e "s|<INSTALL_PATH>|${INSTALL_PATH}|g" rgw-post-install

# Put install_path in utils-post-uninstall
sed -i -e "s|<INSTALL_PATH>|${INSTALL_PATH}|g" rgw-post-uninstall

echo "Creating cortx-rgw RPM with version $VER, release $REL"

cd "$BASE_DIR"

# Create the rgw-pre-install
echo "#!/bin/bash" > rgw-pre-install
echo ""  >> rgw-pre-install
echo "PACKAGE_LIST=\""  >> rgw-pre-install
/bin/cat python_requirements.txt >> rgw-pre-install
echo "\""  >> rgw-pre-install
echo "rc=0
for package in \$PACKAGE_LIST
do
    python3 -m pip freeze | grep \$package > /dev/null
    if [ \$? -ne 0 ]; then
       if [ \$rc -eq 0 ]; then
	  echo \"===============================================\"
       fi
       echo \"Required python package \$package is missing\"
       rc=-1
    fi
done
if [ \$rc -ne 0 ]; then
   echo \"Please install above python packages\"
   echo \"===============================================\"
fi
exit \$rc " >> rgw-pre-install
/bin/chmod +x rgw-pre-install


# Building rpm using setuptool utility

python3 ./setup.py bdist_rpm --release="$REL" --requires python36 \
--pre-install rgw-pre-install \
--post-install rgw-post-install --post-uninstall rgw-post-uninstall


if [ $? -ne 0 ]; then
  echo "RGW build failed !!!"
  exit 1
else
  echo "RPM build successful !!!"
fi
