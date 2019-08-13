project('art-tracer-helper', 'cpp',
  version: '1.0.0',
  default_options: ['cpp_std=c++14'],
)

ndk_toolchain = get_option('ndk_toolchain')
i_system =  join_paths(ndk_toolchain, 'include','c++','4.9.x')
inc = include_directories(
  '../ext/system-core/base/include',
  '../ext/valgrind-3.14.0/include',
  '../ext/valgrind-3.14.0',
  '../ext/art/runtime',
  '../ext/libcxx/include',
)

helper_sources = [
  'helper.cpp',
]
shared_library('art-tracer-helper', helper_sources,
  cpp_args: [
    '-DIMT_SIZE=64',
    '-Wno-inconsistent-missing-override',
    '-nostdinc++',
    '-Wno-invalid-offsetof',
    '-v',
    '-fno-rtti',
  ],
  link_args: [
    '-L' + join_paths(meson.source_root(), '..', 'ext', 'private-libraries'),
    '-L' + join_paths(ndk_toolchain, 'i686-linux-android', 'lib'),
    '-lc++',
    '-lart',
  ],
  include_directories: inc,
)
