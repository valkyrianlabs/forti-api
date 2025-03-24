project('forti-api', 'cpp',
        version : '0.2.2',
        default_options : ['warning_level=3', 'cpp_std=c++23'])

source_root = meson.source_root()

json_dep = dependency('nlohmann_json', required: true)
libcurl_dep = dependency('libcurl', required: true)
gtest_dep = dependency('gtest', required: true, main: false)

global_deps = [json_dep, libcurl_dep]
test_deps = global_deps + gtest_dep

test_sources = []
foreach cpp_file : run_command('find', source_root + '/tests', '-type', 'f', '-name', '*.cpp', check: true).stdout().strip().split('\n')
    test_sources += files(cpp_file)
endforeach

if get_option('buildtype') == 'debug'
    # add_project_arguments('-DENABLE_DEBUG', language: 'cpp')

    test('runTests', executable('runTests', test_sources, dependencies: test_deps))

    executable('forti-api', 'main.cpp',
               dependencies: global_deps,
               include_directories: 'include',
               install: false
    )
endif
