import os
from conans import ConanFile, CMake, tools

class CppJsLibConan(ConanFile):
    name = "CppJsLib"
    version = "0.8"
    license = "MIT"
    author = "MarkusJx"
    url = "https://github.com/MarkusJx/CppJsLib"
    description = "A library for cpp and js communication"
    topics = ("C++", "Javascript")
    no_copy_source = True

    def source(self):
        self.run("git clone https://github.com/MarkusJx/CppJsLib.git")

    def package(self):
        self.copy("*CppJsLib.hpp", dst="include", keep_path=False)
        self.copy("*LICENSE", dst="licenses", keep_path=False)

    def package_id(self):
        self.info.header_only()

    def requirements(self):
        self.requires("nlohmann_json/3.9.1")
        self.requires("cpp-httplib/0.7.15")
        self.requires("websocketpp/0.8.2")

    def package_info(self):
        self.cpp_info.names["cmake_find_package"] = "CppJsLib"
        self.cpp_info.names["cmake_find_package_multi"] = "CppJsLib"
        #self.cpp_info.includedirs = ["include"]