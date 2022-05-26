# Building addb plugin
 ADDB plugin (rgw_addb_plugin.so) is built & bundled in cortx-rgw-integration rpm.
 All addb files which are required to build addb plugin are present as part of cortx-rgw-integration repo.

## Dependencies for building addb plugin
For building RGW ADDB plugin, we require two repositories to be cloned at same level, where cortx-rgw-integration is cloned
  a) cortx-motr
  b) cortx-rgw

## How addb plugin will be generated manually on dev vm
  a) clone its dependent repositories as mentioned above.
  b) generate addb plugin using below commands,
     cd <cortx-rgw-integration>/src/addb_plugin
     make clean
     make plugin

## How addb plugin will be generatd in custom-ci/jenkins job
For building addb plugin using custom-ci/jenkins job,
  a) will require additional parameter '--addb_build'
     e.g. sh build.sh --addb_build
  b) generated rpm will be copy generated addb plugin binary (rgw_addb_plugin.so) to /opt/seagate/cortx/rgw/bin path during rpm installation process. If any failure occurs, the rpm build process will fail with error message.

Note: If '--addb|--addb_build' flag is not provided then rpm build process will skip addb plugin generation process.
