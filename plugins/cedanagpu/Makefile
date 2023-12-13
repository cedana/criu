PLUGIN_NAME		:= cedana_plugin 
PLUGIN_SOBJ		:= cedana_plugin.so

PLUGIN_DIR := /home/nravic/cedana-gpu/

PLUGIN_INCLUDE  	:= -iquote../../include
PLUGIN_INCLUDE  	+= -iquote../../criu/include
PLUGIN_INCLUDE  	+= -iquote../../criu/arch/$(ARCH)/include/
PLUGIN_INCLUDE  	+= -iquote../../

COMPEL                 := ../../compel/compel-host
DEPS_OK 		:= cedana_plugin.so 
DEPS_NOK 		:= ;

__nmk_dir ?= ../../scripts/nmk/scripts/
include $(__nmk_dir)msg.mk

CC      		:= gcc
PLUGIN_CFLAGS  		:= -g -Wall -D _GNU_SOURCE -shared -nostartfiles -fPIC -DCR_PLUGIN_DEFAULT="$(PLUGINDIR)"

all: $(DEPS_OK)

cedana_plugin.so: cedana_plugin.c 
	$(CC) $(PLUGIN_CFLAGS) $(shell $(COMPEL) includes) $^ -o $@ $(PLUGIN_INCLUDE) 

cedana_plugin_clean:
	$(call msg-clean, $@)
	$(Q) $(RM) cedana_plugin.so 
.PHONY:cedana_plugin_clean 

