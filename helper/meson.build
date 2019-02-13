project('art-tracer-helper', 'cpp',
  version: '1.0.0',
  default_options: ['cpp_std=c++14'],
)

inc = include_directories(
  '../ext/art/runtime',
  '../ext/system-core/base/include',
)

helper_sources = [
  'helper.cpp',
]
shared_library('art-tracer-helper', helper_sources,
  cpp_args: [
    '-DIMT_SIZE=64',
    '-Wno-inconsistent-missing-override',
    '-Wno-invalid-offsetof',
  ],
  include_directories: inc,
)
