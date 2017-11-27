PKG_NAME=compas
PKG_URL=https://github.com/cgundogan/compas
PKG_VERSION=4dc6ba1eba255ef9842c6183b353f8b2b4cdcb59
PKG_LICENSE="LGPL 2.1"

.PHONY: all

all: TARGET_ARCH:=
all: git-download
	$(MAKE) -C $(PKG_BUILDDIR)
	cp $(PKG_BUILDDIR)/libcompas.a ${BINDIR}/compas.a

include $(RIOTBASE)/pkg/pkg.mk
