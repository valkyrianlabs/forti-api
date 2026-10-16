project('forti-api', 'cpp',
        version : '1.0.2',
        meson_version : '>=1.3.0',
        default_options : ['warning_level=3', 'cpp_std=c++23'])

# Header-only. nlohmann/json is vendored (third_party/nlohmann/README.md); libcurl is the only
# system dependency (apt: libcurl4-openssl-dev, macOS: the SDK's libcurl or brew curl).
curl_dep = dependency('libcurl')

forti_api_dep = declare_dependency(
    include_directories : include_directories('include', 'third_party/nlohmann/include'),
    dependencies : curl_dep)
meson.override_dependency('forti-api', forti_api_dep)

# Everything below is for a standalone build. As a Meson subproject (consumers use forti_api_dep or
# dependency('forti-api')), forti-api builds no example or tests and installs nothing: no headers
# and no .pc next to the consumer's files.
if meson.is_subproject()
    subdir_done()
endif

# The vendored nlohmann/json installs under forti_api/third_party so it never collides with a
# system nlohmann-json (/usr/include/nlohmann); forti-api.pc adds that directory to the include path.
install_headers('include/forti_api.hpp')
install_subdir('include/forti_api', install_dir : get_option('includedir'))
install_subdir('third_party/nlohmann/include/nlohmann',
               install_dir : get_option('includedir') / 'forti_api' / 'third_party')
install_data('third_party/nlohmann/LICENSE.MIT',
             install_dir : get_option('includedir') / 'forti_api' / 'third_party' / 'nlohmann')

# Architecture-independent, so the .pc goes to datadir rather than the multiarch libdir.
import('pkgconfig').generate(
    name : 'forti-api',
    description : 'Header-only C++23 client for the FortiGate REST API',
    subdirs : ['.', 'forti_api/third_party'],
    libraries : curl_dep,
    install_dir : get_option('datadir') / 'pkgconfig')

# Targets opt out of implicit include directories: on case-insensitive filesystems (macOS) the
# source root's VERSION file would otherwise shadow the standard <version> header.

# Examples double as a compile check of the umbrella header; never installed.
executable('inventory', 'examples/inventory.cpp', dependencies : forti_api_dep, implicit_include_directories : false)

# Unit tests: network-free (a scripted transport), run by CI.
gtest_dep = dependency('gtest', main : true, required : get_option('tests'))
if gtest_dep.found()
    test('unit', executable('unitTests',
                            'tests/unit/test_client.cpp',
                            'tests/unit/test_download.cpp',
                            'tests/unit/test_transport.cpp',
                            'tests/unit/test_live_guard.cpp',
                            'tests/unit/test_field.cpp',
                            'tests/unit/test_endpoint.cpp',
                            'tests/unit/test_helpers.cpp',
                            dependencies : [forti_api_dep, gtest_dep],
                            implicit_include_directories : false),
         suite : 'unit')
endif

# Live tests run against a real FortiGate (AGENTS.md, .env.example): opt-in, and in their own suite so
# `meson test --suite unit` never touches a device. CI compiles them but never runs them.
if get_option('live_tests')
    gtest_nomain_dep = dependency('gtest', main : false)
    test('fortigate', executable('liveTests',
                                 'tests/live/main.cpp',
                                 'tests/live/test_backup.cpp',
                                 'tests/live/test_coverage.cpp',
                                 'tests/live/test_crud.cpp',
                                 'tests/live/test_dnsfilter.cpp',
                                 'tests/live/test_generated.cpp',
                                 'tests/live/test_system.cpp',
                                 'tests/live/test_threat_feed.cpp',
                                 dependencies : [forti_api_dep, gtest_nomain_dep],
                                 implicit_include_directories : false),
         suite : 'live', timeout : 300, is_parallel : false)
endif
