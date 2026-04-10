# xSight — Top-level Makefile
# Delegates to sub-project Makefiles (node/ and controller/)

.PHONY: all node controller clean help

all: node

node:
	$(MAKE) -C node all

controller:
	$(MAKE) -C controller all

clean:
	$(MAKE) -C node clean
	-$(MAKE) -C controller clean

help:
	@echo "xSight top-level targets:"
	@echo "  all        — build node (default)"
	@echo "  node       — build xsight-node"
	@echo "  controller — build xsight-controller"
	@echo "  clean      — clean all sub-projects"
