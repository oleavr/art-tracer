build_platform := $(shell uname -s | tr '[A-Z]' '[a-z]' | sed 's,^darwin$$,macos,')

all: build

build: build/libart-tracer-helper.so

deploy: build/libart-tracer-helper.so
	adb push build/libart-tracer-helper.so /data/local/tmp/
	adb shell 'su root chown root:root /data/local/tmp/libart-tracer-helper.so'
	adb shell 'su root chmod 755 /data/local/tmp/libart-tracer-helper.so'
	adb shell 'su root chcon u:object_r:frida_file:s0 /data/local/tmp/libart-tracer-helper.so'
	adb shell 'su root mv /data/local/tmp/libart-tracer-helper.so /data/local/tmp/re.frida.server/'

build/build.ninja: meson.build
	rm -rf build
	sed -i "s@ndk_toolchain_value@$$NDK_TOOLCHAIN@g" meson_options.txt
	   rm -rf build && mkdir build
	   meson \
			--cross-file cross_file.txt \
			build .
	@touch $@

build/libart-tracer-helper.so: build/build.ninja helper.cpp
	@cd ../ext/art/runtime \
		&& for header in runtime.h class_linker.h java_vm_ext.h thread.h art_method.h interpreter/shadow_frame.h ; do \
			sed -i -e "s/private:/public:/g" $$header; \
			sed -i -e "s/protected:/public:/g" $$header; \
		done
	ninja -C build
	@touch $@

.PHONY: build deploy
.SECONDARY:
