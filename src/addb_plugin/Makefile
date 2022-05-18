MOTR_SRC_DIR="../../../cortx-motr"

.PHONY: all plugin clean help

all help:
	@printf "Usage: make COMMAND\n"
	@printf "\n"
	@printf "Makefile builds RGW ADDB plugin for m0addb2dump utility."
	@printf " It allows to detect RGW ADDB probes and parse them to textual "
	@printf "ADDB dumps for further processing.\n"
	@printf "\n"
	@printf "Commands:\n"
	@printf "Build RGW ADDB plugin:\n"
	@printf "\tmake plugin\n"
	@printf "Remove RGW ADDB plugin:\n"
	@printf "\tmake clean\n"
	@printf "Print this message:\n"
	@printf "\tmake\n"
	@printf "\tmake help\n"
	@printf "\n"

plugin: rgw_addb_plugin.so
	@printf "RGW ADDB pluging built successfully\n"

%.o: %.c
	gcc -I${MOTR_SRC_DIR} -DM0_INTERNAL= -DM0_EXTERNAL=extern -fno-common -Wall -Wno-attributes -Werror -fPIC $< -c

rgw_addb_plugin.so: rgw_addb_plugin.o rgw_addb_map.o
	gcc -shared -o $@ $^ 

clean:
	rm -rf rgw_addb_plugin.so rgw_addb_plugin.o rgw_addb_map.o
