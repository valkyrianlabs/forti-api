project('forti-api', 'cpp',
        version : '0.2.2',
        meson_version : '>=1.3.0',
        default_options : ['warning_level=3', 'cpp_std=c++23'])

# Header-only. nlohmann/json is vendored (third_party/nlohmann/README.md); libcurl is the only
# system dependency (apt: libcurl4-openssl-dev, macOS: the SDK's libcurl or brew curl).
curl_dep = dependency('libcurl')

forti_api_dep = declare_dependency(
    include_directories : include_directories('include', 'third_party/nlohmann/include'),
    dependencies : curl_dep)
meson.override_dependency('forti-api', forti_api_dep)

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

# Compile check of the umbrella header; never installed.
executable('forti-api', 'main.cpp', dependencies : forti_api_dep, implicit_include_directories : false)

# The tests run against a live FortiGate (see .env.example), so they are optional.
gtest_dep = dependency('gtest', main : false, required : get_option('tests'))
if gtest_dep.found()
    test('fortigate', executable('runTests',
                                 'tests/main.cpp',
                                 'tests/test_dns_filter.cpp',
                                 'tests/test_system.cpp',
                                 'tests/test_threat_feed.cpp',
                                 dependencies : [forti_api_dep, gtest_dep],
                                 implicit_include_directories : false),
         timeout : 120)
endif
