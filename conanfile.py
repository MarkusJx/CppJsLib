from conans import ConanFile, CMake, tools


class CppJsLibConan(ConanFile):
    name = "CppJsLib"
    version = "0.8"
    license = "MIT"
    author = "MarkusJx"
    url = "https://github.com/MarkusJx/CppJsLib"
    description = "test"
    topics = ("C++", "Javascript")
    exports_sources = "include/*"
    no_copy_source = True
    requires = ["nlohmann_json/3.9.1@", "cpp-httplib/0.7.15@", "websocketpp/0.8.2@"]

    def source(self):
        self.run("git clone https://github.com/MarkusJx/CppJsLib.git")
        pass

    def package(self):
        self.copy("*.hpp")
        self.copy("license", dst="licenses",  ignore_case=True, keep_path=False)
