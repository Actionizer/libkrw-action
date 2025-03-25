ABI_VERSION     := 0
CURRENT_VERSION := 1.1.2
COMPAT_VERSION  := 1.0.0
#PACKAGE_DOMAIN  := net.siguza.

TARGET           = libkrw
SRC              = src
INC              = include
LR_INC         	 = external/libroot/src
LR_LIB         	 = external/libroot
PKG              = pkg

ifeq ($(ROOTLESS),1)
ROOTLESS_ARCH	= 64
ROOTLESS_PATH	= /var/jb
endif
ifeq ($(DEBUG),1)
OPT				= -O0
DEBUG_FLAGS		= -DDEBUG=1 -g
else
ifeq ($(shell type llvm-strip >/dev/null 2>&1 && echo 1),1)
STRIP			?= llvm-strip
else
ifeq ($(shell type xcrun strip >/dev/null 2>&1 && echo 1),1)
STRIP			?= strip
else
ifeq ($(shell type strip >/dev/null 2>&1 && echo 1),1)
STRIP			?= strip
endif
endif
endif
OPT				= -O3
DEBUG_FLAGS		= -DNDEBUG=1
endif

IGCC            ?= xcrun -sdk iphoneos clang -arch arm64 -arch arm64e
IGCC_FLAGS      ?= -Wall $(OPT) $(DEBUG_FLAGS) -I$(INC) -I$(LR_INC) -L$(LR_LIB) -lroot_dyn_iphoneos-arm64 -DTARGET=\"$(TARGET)\"
DYLIB_FLAGS     ?= -shared -miphoneos-version-min=7.0 -Wl,-install_name,$(ROOTLESS_PATH)/usr/lib/$(TARGET).$(ABI_VERSION).dylib -Wl,-current_version,$(CURRENT_VERSION) -Wl,-compatibility_version,$(COMPAT_VERSION) -Wl,-no_warn_inits
PLUGIN_FLAGS 	?= -shared -miphoneos-version-min=7.0 -Wl,-install_name,$(ROOTLESS_PATH)/usr/lib/libkrw/$(TARGET)_tfp0.$(ABI_VERSION).dylib -Wl,-current_version,$(CURRENT_VERSION) -Wl,-compatibility_version,$(COMPAT_VERSION) -Wl,-no_warn_inits
SIGN            ?= codesign
SIGN_FLAGS      ?= -s -
TAPI            ?= xcrun -sdk iphoneos tapi
TAPI_FLAGS      ?= stubify --no-uuids --filetype=tbd-v2
TAR             ?= bsdtar
TAR_FLAGS       ?= --uid 0 --gid 0
DEB_ARCH		?= iphoneos-arm$(ROOTLESS_ARCH)

.PHONY: all deb clean

all: $(TARGET).$(ABI_VERSION).dylib $(TARGET)-tfp0.dylib $(TARGET).tbd

deb: $(PACKAGE_DOMAIN)$(TARGET)$(ABI_VERSION)_$(CURRENT_VERSION)_iphoneos-arm$(ROOTLESS_ARCH).deb $(PACKAGE_DOMAIN)$(TARGET)-dev_$(CURRENT_VERSION)_iphoneos-arm$(ROOTLESS_ARCH).deb $(PACKAGE_DOMAIN)$(TARGET)$(ABI_VERSION)-tfp0_$(CURRENT_VERSION)_iphoneos-arm$(ROOTLESS_ARCH).deb

$(TARGET).$(ABI_VERSION).dylib: $(SRC)/libkrw.c $(INC)/*.h
	@$(MAKE) -C external/libroot
	$(IGCC) $(IGCC_FLAGS) $(DYLIB_FLAGS) -o $@ $(SRC)/libkrw.c
ifdef STRIP
	$(STRIP) -x $@
#	$(info $(shell $(STRIP)))
endif
	$(SIGN) $(SIGN_FLAGS) $@

$(TARGET)-tfp0.dylib: $(SRC)/libkrw_tfp0.c $(INC)/*.h
	@$(MAKE) -C external/libroot
	$(IGCC) $(IGCC_FLAGS) $(PLUGIN_FLAGS) -o $@ $(SRC)/libkrw_tfp0.c
ifdef STRIP
	$(STRIP) -x $@
#	$(info $(shell $(STRIP)))
endif
	$(SIGN) $(SIGN_FLAGS) $@

$(TARGET).tbd: $(TARGET).$(ABI_VERSION).dylib
	$(TAPI) $(TAPI_FLAGS) -o $@ $<

$(PACKAGE_DOMAIN)$(TARGET)$(ABI_VERSION)_$(CURRENT_VERSION)_iphoneos-arm$(ROOTLESS_ARCH).deb: $(PKG)/bin/control.tar.gz $(PKG)/bin/data.tar.lzma $(PKG)/bin/debian-binary
	( cd "$(PKG)/bin"; ar -cr "../../$@" 'debian-binary' 'control.tar.gz' 'data.tar.lzma'; )

$(PACKAGE_DOMAIN)$(TARGET)-dev_$(CURRENT_VERSION)_iphoneos-arm$(ROOTLESS_ARCH).deb: $(PKG)/dev/control.tar.gz $(PKG)/dev/data.tar.lzma $(PKG)/dev/debian-binary
	( cd "$(PKG)/dev"; ar -cr "../../$@" 'debian-binary' 'control.tar.gz' 'data.tar.lzma'; )

$(PACKAGE_DOMAIN)$(TARGET)$(ABI_VERSION)-tfp0_$(CURRENT_VERSION)_iphoneos-arm$(ROOTLESS_ARCH).deb: $(PKG)/plugin/control.tar.gz $(PKG)/plugin/data.tar.lzma $(PKG)/plugin/debian-binary
	( cd "$(PKG)/plugin"; ar -cr "../../$@" 'debian-binary' 'control.tar.gz' 'data.tar.lzma'; )

$(PKG)/bin/control.tar.gz: $(PKG)/bin/control
	$(TAR) $(TAR_FLAGS) -czf $@ --format ustar -C $(PKG)/bin --exclude '.DS_Store' --exclude '._*' ./control

$(PKG)/dev/control.tar.gz: $(PKG)/dev/control
	$(TAR) $(TAR_FLAGS) -czf $@ --format ustar -C $(PKG)/dev --exclude '.DS_Store' --exclude '._*' ./control

$(PKG)/plugin/control.tar.gz: $(PKG)/plugin/control
	$(TAR) $(TAR_FLAGS) -czf $@ --format ustar -C $(PKG)/plugin --exclude '.DS_Store' --exclude '._*' ./control

$(PKG)/bin/data.tar.lzma: $(PKG)/bin/data$(ROOTLESS_PATH)/usr/lib/$(TARGET).$(ABI_VERSION).dylib
	$(TAR) $(TAR_FLAGS) -c --lzma -f $@ --format ustar -C $(PKG)/bin/data --exclude '.DS_Store' --exclude '._*' ./

$(PKG)/dev/data.tar.lzma: $(PKG)/dev/data$(ROOTLESS_PATH)/usr/lib/$(TARGET).dylib $(PKG)/dev/data$(ROOTLESS_PATH)/usr/include/$(TARGET).h $(PKG)/dev/data$(ROOTLESS_PATH)/usr/include/$(TARGET)_plugin.h
	$(TAR) $(TAR_FLAGS) -c --lzma -f $@ --format ustar -C $(PKG)/dev/data --exclude '.DS_Store' --exclude '._*' ./

$(PKG)/plugin/data.tar.lzma: $(PKG)/plugin/data$(ROOTLESS_PATH)/usr/lib/libkrw/$(TARGET)-tfp0.dylib
	$(TAR) $(TAR_FLAGS) -c --lzma -f $@ --format ustar -C $(PKG)/plugin/data --exclude '.DS_Store' --exclude '._*' ./

$(PKG)/bin/debian-binary: | $(PKG)/bin
	echo '2.0' > $@

$(PKG)/dev/debian-binary: | $(PKG)/dev
	echo '2.0' > $@

$(PKG)/plugin/debian-binary: | $(PKG)/plugin
	echo '2.0' > $@

$(PKG)/bin/control: | $(PKG)/bin
	( echo 'Package: $(PACKAGE_DOMAIN)$(TARGET)$(ABI_VERSION)'; \
	  echo 'Name: $(TARGET)$(ABI_VERSION)'; \
	  echo 'Author: Siguza'; \
	  echo 'Maintainer: Cryptiiiic'; \
	  echo 'Architecture: iphoneos-arm$(ROOTLESS_ARCH)'; \
	  echo 'Version: $(CURRENT_VERSION)'; \
	  echo 'Priority: optional'; \
	  echo 'Section: Development'; \
	  echo 'Description: Nice kernel r/w API'; \
	  echo 'Homepage: https://github.com/Siguza/libkrw/'; \
	) > $@

$(PKG)/dev/control: | $(PKG)/dev
	( echo 'Package: $(PACKAGE_DOMAIN)$(TARGET)-dev'; \
	  echo 'Depends: $(PACKAGE_DOMAIN)$(TARGET)$(ABI_VERSION)'; \
	  echo 'Name: $(TARGET)-dev'; \
	  echo 'Author: Siguza'; \
	  echo 'Maintainer: Cryptiiiic'; \
	  echo 'Architecture: iphoneos-arm$(ROOTLESS_ARCH)'; \
	  echo 'Version: $(CURRENT_VERSION)'; \
	  echo 'Priority: optional'; \
	  echo 'Section: Development'; \
	  echo 'Description: $(TARGET) headers'; \
	  echo 'Homepage: https://github.com/Siguza/libkrw/'; \
	) > $@

$(PKG)/plugin/control: | $(PKG)/plugin
	( echo 'Package: $(PACKAGE_DOMAIN)$(TARGET)$(ABI_VERSION)-tfp0'; \
	  echo 'Depends: $(PACKAGE_DOMAIN)$(TARGET)$(ABI_VERSION)'; \
	  echo 'Name: $(TARGET)$(ABI_VERSION)-tfp0'; \
	  echo 'Author: Siguza'; \
	  echo 'Maintainer: Cryptiiiic'; \
	  echo 'Architecture: iphoneos-arm$(ROOTLESS_ARCH)'; \
	  echo 'Version: $(CURRENT_VERSION)'; \
	  echo 'Priority: optional'; \
	  echo 'Provides: $(TARGET)$(ABI_VERSION)-plugin'; \
	  echo 'Section: Development'; \
	  echo 'Description: $(TARGET) tfp0 plugin'; \
	  echo 'Homepage: https://github.com/Siguza/libkrw/'; \
	) > $@

$(PKG)/bin/data$(ROOTLESS_PATH)/usr/lib/$(TARGET).$(ABI_VERSION).dylib: $(TARGET).$(ABI_VERSION).dylib | $(PKG)/bin/data$(ROOTLESS_PATH)/usr/lib
	cp $< $@

$(PKG)/dev/data$(ROOTLESS_PATH)/usr/lib/$(TARGET).dylib: | $(PKG)/dev/data$(ROOTLESS_PATH)/usr/lib
	( cd "$(PKG)/dev/data$(ROOTLESS_PATH)/usr/lib"; ln -sf $(TARGET).$(ABI_VERSION).dylib $(TARGET).dylib; )

$(PKG)/dev/data$(ROOTLESS_PATH)/usr/include/%.h: $(INC)/%.h | $(PKG)/dev/data$(ROOTLESS_PATH)/usr/include
	cp $< $@

$(PKG)/plugin/data$(ROOTLESS_PATH)/usr/lib/libkrw/$(TARGET)-tfp0.dylib: $(TARGET)-tfp0.dylib | $(PKG)/plugin/data$(ROOTLESS_PATH)/usr/lib/libkrw
	cp $< $@

$(PKG)/bin $(PKG)/dev $(PKG)/plugin $(PKG)/bin/data$(ROOTLESS_PATH)/usr/lib $(PKG)/dev/data$(ROOTLESS_PATH)/usr/lib $(PKG)/dev/data$(ROOTLESS_PATH)/usr/include $(PKG)/plugin/data$(ROOTLESS_PATH)/usr/lib/libkrw:
	mkdir -p $@

clean:
	rm -f *.dylib *.deb
	rm -rf $(PKG)
	git checkout $(TARGET).tbd
