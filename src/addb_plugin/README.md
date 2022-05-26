# Building addb plugin
 Addb plugin (rgw_addb_plugin.so) is build as part of cortx-rgw-integration rpm.
 All addb files which are required to build addb plugin are present as part of cortx-rgw-integration repo.

## Dependencies for building addb plugin
For building addb, we require two repositories to be cloned.
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
  a) cortx-rgw-integration's build script will require additional parameter
     e.g. sh build.sh --addb_build
  b) this will be handled by RE team in jenkins's script.
  c) generated rpm will be copy generated addb plugin binary (rgw_addb_plugin.so) to /opt/seagate/cortx/rgw/bin path during rpm installation process. If any failure occurs, the rpm build process will fail with error message.

Note: If '--addb|--aaddb_build' flag is not provided then rpm build process will skip addb plugin generation process.
