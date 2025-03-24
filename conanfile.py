from conan import ConanFile
from conan.tools.meson import Meson
from conan.tools.files import copy


class Pkg(ConanFile):
    name = "forti-api"
    version = "0.2.2"
    author = "Cooper Larson | cooper.larson1@gmail.com"
    url = ""
    description = "FortiGate API interface"
    topics = ("c++", "security")
    settings = "os", "compiler", "arch", "build_type"
    generators = "PkgConfigDeps", "MesonToolchain"
    exports_sources = "meson.build", "include/*", "tests/*", "main.cpp"

    def layout(self):
        self.folders.source = '.'
        self.folders.build = 'build/meson'
        self.folders.generators = 'build/generators'
        self.folders.package = 'build/package'

    def requirements(self):
        self.requires('nlohmann_json/3.11.3')
        self.requires('libcurl/8.9.1')
        self.test_requires('gtest/1.14.0')

    def build(self):
        meson = Meson(self)
        meson.configure()
        meson.build()

    def test(self):
        meson = Meson(self)
        meson.test()

    def package(self):
        copy(self, "*.hpp", self.source_folder, self.package_folder)
        meson = Meson(self)
        meson.install()

    def package_info(self):
        self.cpp_info.includedirs = ['include']
        self.cpp_info.bindirs = []
        self.cpp_info.libdirs = []

    def package_id(self):
        self.info.clear()
