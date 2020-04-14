//
// Created by markus on 14/03/2020.
//

#include <utility>
#include <vector>
#include <mutex>
#include <utils/loggingfunc.hpp>

#define CPPJSLIB_BUILD_JNI_DLL

#include "../CppJsLib.hpp"
#include "com_markusjx_cppjslib_nt_CppJsLibNative.h"

#ifdef CPPJSLIB_UNIX
typedef int errno_t;
#endif

#define ELIF_CMP_JT(s1) } else if (strcmp(s1, jType) == 0) {
#define JAVA_STRING_CLS() env->FindClass("Ljava/lang/String;")
#define SET_JVM() if (jvm == nullptr) env->GetJavaVM(&jvm)
#define CHECK_JAVA_EXCEPTION() if (env->ExceptionCheck()) env->ExceptionDescribe()

using std::string;
using std::vector;

JavaVM *jvm = nullptr;

jobject eF = nullptr, lF = nullptr;

errno_t getEnv(JNIEnv *&env) {
    int getEnvStat = jvm->GetEnv((void **) &env, JNI_VERSION_1_8);
    if (getEnvStat == JNI_EDETACHED) {
        if (jvm->AttachCurrentThread((void **) &env, nullptr) != 0) {
            errorF("[CppJsLib] Failed to attach");
            return -2;
        } else {
            return 0;
        }
    } else if (getEnvStat == JNI_EVERSION) {
        errorF("[CppJsLib] GetEnv: version not supported");
        return -1;
    } else if (getEnvStat == JNI_OK) {
        return 0;
    } else {
        return 1;
    }
}

class J_JsFunction_Template {
public:
    J_JsFunction_Template(string _name, string *args, unsigned short nArgs, CppJsLib::WebGUI *wGui) {
        name = std::move(_name);
        argTypes = new string[nArgs];
        for (int i = 0; i < nArgs; ++i) {
            argTypes[i] = args[i];
        }
        argc = nArgs;
        webGui = wGui;
    }

    ~J_JsFunction_Template() {
        delete[] argTypes;
    }

    string name;
    string *argTypes;
    unsigned short argc;
    CppJsLib::WebGUI *webGui;
};

class J_VoidJsFunction : public J_JsFunction_Template {
public:
    J_VoidJsFunction(string name, string *args, unsigned short nArgs, CppJsLib::WebGUI *wGui) : J_JsFunction_Template(
            std::move(name), args, nArgs, wGui) {}

    void operator()(string *args) {
        vector<string> argV;
        argV.reserve(argc);
        for (int i = 0; i < argc; i++) {
            argV.push_back(args[i]);
        }

        char *fName = strdup(name.c_str());
        CppJsLib::util::callJsFunc(webGui, &argV, fName);
        free(fName);
    }
};

class J_JsFunction : public J_JsFunction_Template {
public:
    J_JsFunction(string _name, string rt, string *args, unsigned short nArgs, int _wait, CppJsLib::WebGUI *wGui)
            : J_JsFunction_Template(std::move(_name), args, nArgs, wGui), responseReturns() {
        wait = _wait;
        returnType = std::move(rt);
    }

    vector<string> operator()(string *args) {
        vector<string> argV;
        argV.reserve(argc);
        for (int i = 0; i < argc; i++) {
            argV.push_back(args[i]);
        }

        char *fName = strdup(name.c_str());
        CppJsLib::util::callJsFunc(webGui, &argV, fName, &responseReturns, wait);
        free(fName);

        vector<string> tmp;
        for (const std::string &s : responseReturns) {
            tmp.push_back(CppJsLib::util::ConvertString<string>(s));
        }
        vector<std::string>().swap(responseReturns);

        return tmp;
    }

    ~J_JsFunction() {
        if (!responseReturns.empty()) {
            vector<std::string>().swap(responseReturns);
        }
    };

    int wait;
    string returnType;
    vector<std::string> responseReturns;
};

class WebGUIContainer {
public:
    WebGUIContainer(int id, const char *base_dir) : v(), jv(), m() {
        this->id = id;
        webGui = new CppJsLib::WebGUI(base_dir);
    }

    WebGUIContainer(int id, const char *base_dir, const char *cert_path, const char *private_key_path,
                    unsigned short websocket_fallback) : v(), jv(), m() {
        this->id = id;
        webGui = new CppJsLib::WebGUI(base_dir, cert_path, private_key_path, websocket_fallback);
    }

    int insertJsFunction(string name, string returnType, string *argTypes, int num_args, int wait) {
        auto *fn = new J_JsFunction(std::move(name), std::move(returnType), argTypes, num_args, wait, webGui);

        m.lock();
        v.push_back(fn);
        int res = (int) v.size() - 1;
        m.unlock();

        return res;
    }

    int insertVoidJsFunction(string name, string *argTypes, int num_args) {
        auto *fn = new J_VoidJsFunction(std::move(name), argTypes, num_args, webGui);

        m.lock();
        v.push_back(fn);
        int res = (int) v.size() - 1;
        m.unlock();

        return res;
    }

    ~WebGUIContainer() {
        if (jvm) {
            JNIEnv *env;
            errno_t err = getEnv(env);
            if (err) {
                errorF("[CppJsLib] Could not initialize JNIEnv");
            } else {
                for (jobject j : jv) {
                    env->DeleteGlobalRef(j);
                }
            }
        }
        for (J_JsFunction_Template *fn : v) {
            delete fn;
        }
        delete webGui;
    }

    int id;
    CppJsLib::WebGUI *webGui;
    std::mutex m;
    vector<jobject> jv;
    vector<J_JsFunction_Template *> v;
};

vector<WebGUIContainer *> instances;
std::mutex mtx;

int lastID = 0;

jboolean isFalse = (jboolean) false;

WebGUIContainer *findContainer(int id) {
    for (WebGUIContainer *c : instances) {
        if (c->id == id) {
            return c;
        }
    }
    return nullptr;
}

std::string getTypeName(const char *jType) {
    if (strcmp(jType, "int") == 0) {
        return "int";
    ELIF_CMP_JT("[I")
        return "int[]";
    ELIF_CMP_JT("java.lang.String")
        return "string";
    ELIF_CMP_JT("[Ljava.lang.String;")
        return "string[]";
    ELIF_CMP_JT("char")
        return "char";
    ELIF_CMP_JT("[C")
        return "char[]";
    ELIF_CMP_JT("boolean")
        return "bool";
    ELIF_CMP_JT("[Z")
        return "bool[]";
    ELIF_CMP_JT("float")
        return "float";
    ELIF_CMP_JT("[F")
        return "float[]";
    ELIF_CMP_JT("double")
        return "double";
    ELIF_CMP_JT("[D")
        return "double[]";
    ELIF_CMP_JT("void")
        return "void";
    } else {
        return "";
    }
}

void
CppJsLib::WebGUI::exportJavaFunction(const std::string &name, std::string returnType, std::string *argTypes,
                                     int numArgs, const std::function<std::string(std::string *, int)> &fn) {
    std::string fnString = std::move(returnType);
    fnString.append(" ").append(name).append("(");
    for (int i = 0; i < numArgs; i++) {
        if (i > 0) fnString.append(", ");
        fnString.append(argTypes[i]);
    }
    fnString.append(")");

    this->insertToInitMap(strdup(name.c_str()), strdup(fnString.c_str()));
    std::string r = "/callfunc_";
    r.append(name);

    callFromPost(r.c_str(), [numArgs, this, fn](const std::string &req_body) {
        int size = 0;
        auto *argArr = util::parseJSONInput(&size, req_body);

        if (size != numArgs) {
            err("[CppJsLib] Argument count from JS does not match");
            return "";
        }

        return fn(argArr, size).c_str();
    });
}

/*
 * Class:     markusjx_cppjslib_nt_CppJsLibNative
 * Method:    initWebGUI
 * Signature: (Ljava/lang/String;)I
 */
JNIEXPORT jint JNICALL Java_com_markusjx_cppjslib_nt_CppJsLibNative_initWebGUI__Ljava_lang_String_2(JNIEnv *env, jclass,
                                                                                                    jstring base_dir) {
    SET_JVM();
    mtx.lock();
    const char *dir = env->GetStringUTFChars(base_dir, &isFalse);
    instances.push_back(new WebGUIContainer(lastID, dir));
    env->ReleaseStringUTFChars(base_dir, dir);

    int tmp = lastID;
    lastID++;
    mtx.unlock();

    return tmp;
}

/*
 * Class:     markusjx_cppjslib_nt_CppJsLibNative
 * Method:    initWebGUI
 * Signature: (Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;I)I
 */
JNIEXPORT jint
JNICALL Java_com_markusjx_cppjslib_nt_CppJsLibNative_initWebGUI__Ljava_lang_String_2Ljava_lang_String_2Ljava_lang_String_2I(
        JNIEnv *env, jclass, jstring base_dir, jstring cert_path, jstring private_key_path,
        jint websocket_fallback_plain) {
    SET_JVM();
    mtx.lock();

    auto dir = env->GetStringUTFChars(base_dir, &isFalse);
    auto c_path = env->GetStringUTFChars(cert_path, &isFalse);
    auto p_k_path = env->GetStringUTFChars(private_key_path, &isFalse);

    instances.push_back(new WebGUIContainer(lastID, dir, c_path, p_k_path, (unsigned short) websocket_fallback_plain));

    env->ReleaseStringUTFChars(base_dir, dir);
    env->ReleaseStringUTFChars(cert_path, c_path);
    env->ReleaseStringUTFChars(private_key_path, p_k_path);

    int id = lastID;
    lastID++;
    mtx.unlock();

    return id;
}

/*
 * Class:     markusjx_cppjslib_nt_CppJsLibNative
 * Method:    running
 * Signature: (I)Z
 */
JNIEXPORT jboolean JNICALL Java_com_markusjx_cppjslib_nt_CppJsLibNative_running(JNIEnv *env, jclass, jint id) {
    SET_JVM();
    WebGUIContainer *c = findContainer(id);
    if (c)
        return c->webGui->isRunning();
    else
        return false;
}

/*
 * Class:     markusjx_cppjslib_nt_CppJsLibNative
 * Method:    stopped
 * Signature: (I)Z
 */
JNIEXPORT jboolean JNICALL Java_com_markusjx_cppjslib_nt_CppJsLibNative_stopped(JNIEnv *env, jclass, jint id) {
    SET_JVM();
    WebGUIContainer *c = findContainer(id);
    if (c)
        return !c->webGui->isRunning();
    else
        return false;
}

/*
 * Class:     markusjx_cppjslib_nt_CppJsLibNative
 * Method:    checkPorts
 * Signature: (IZ)V
 */
JNIEXPORT void
JNICALL Java_com_markusjx_cppjslib_nt_CppJsLibNative_checkPorts__IZ(JNIEnv *env, jclass, jint id, jboolean val) {
    SET_JVM();
    WebGUIContainer *c = findContainer(id);
    if (c)
        c->webGui->check_ports = (bool) val;
}

/*
 * Class:     markusjx_cppjslib_nt_CppJsLibNative
 * Method:    checkPorts
 * Signature: (I)Z
 */
JNIEXPORT jboolean JNICALL Java_com_markusjx_cppjslib_nt_CppJsLibNative_checkPorts__I(JNIEnv *env, jclass, jint id) {
    SET_JVM();
    WebGUIContainer *c = findContainer(id);
    if (c)
        return c->webGui->check_ports;
    else
        return false;
}

/*
 * Class:     markusjx_cppjslib_nt_CppJsLibNative
 * Method:    setLogger
 * Signature: (ILmarkusjx/cppjslib/interfaces/LoggingFunction;)V
 */
JNIEXPORT void
JNICALL Java_com_markusjx_cppjslib_nt_CppJsLibNative_setLogger__ILcom_markusjx_cppjslib_interfaces_LoggingFunction_2(
        JNIEnv *env, jclass, jint id, jobject loggingFunction) {
    SET_JVM();
    WebGUIContainer *c = findContainer(id);
    if (c) {
        jobject loggingF = env->NewGlobalRef(loggingFunction);
        c->jv.push_back(loggingF);

        c->webGui->setLogger([loggingF](const std::string &s) {
            JNIEnv *env;
            errno_t err = getEnv(env);
            if (err) {
                std::cerr << "[CppJsLib] Could not initialize JNIEnv. Error: " << err << std::endl;
                return;
            }

            jclass LoggingFunction = env->FindClass("Lcom/markusjx/cppjslib/interfaces/LoggingFunction;");
            jmethodID log = env->GetMethodID(LoggingFunction, "log", "(Ljava/lang/String;)V");
            jstring msg = env->NewStringUTF(s.c_str());

            env->CallVoidMethod(loggingF, log, msg);
            CHECK_JAVA_EXCEPTION();
        });
    }
}

/*
 * Class:     markusjx_cppjslib_nt_CppJsLibNative
 * Method:    setError
 * Signature: (ILmarkusjx/cppjslib/interfaces/LoggingFunction;)V
 */
JNIEXPORT void
JNICALL Java_com_markusjx_cppjslib_nt_CppJsLibNative_setError__ILcom_markusjx_cppjslib_interfaces_LoggingFunction_2(
        JNIEnv *env, jclass, jint id, jobject errorFunction) {
    SET_JVM();
    WebGUIContainer *c = findContainer(id);
    if (c) {
        jobject errorF = env->NewGlobalRef(errorFunction);
        c->jv.push_back(errorF);

        c->webGui->setError([errorF](const std::string &s) {
            JNIEnv *env;
            errno_t err = getEnv(env);
            if (err) {
                std::cerr << "[CppJsLib] Could not initialize JNIEnv. Error: " << err << std::endl;
                return;
            }

            jclass LoggingFunction = env->FindClass("Lcom/markusjx/cppjslib/interfaces/LoggingFunction;");
            jmethodID log = env->GetMethodID(LoggingFunction, "log", "(Ljava/lang/String;)V");
            jstring msg = env->NewStringUTF(s.c_str());

            env->CallVoidMethod(errorF, log, msg);
            CHECK_JAVA_EXCEPTION();
        });
    }
}

/*
 * Class:     markusjx_cppjslib_nt_CppJsLibNative
 * Method:    setLogger
 * Signature: (Lmarkusjx/cppjslib/interfaces/LoggingFunction;)V
 */
JNIEXPORT void
JNICALL Java_com_markusjx_cppjslib_nt_CppJsLibNative_setLogger__Lcom_markusjx_cppjslib_interfaces_LoggingFunction_2(
        JNIEnv *env,
        jclass,
        jobject loggingFunction) {
    SET_JVM();
    jobject loggingF = env->NewGlobalRef(loggingFunction);
    if (lF)
        env->DeleteGlobalRef(lF);
    lF = loggingF;

    CppJsLib::setLogger([loggingF](const std::string &s) {
        JNIEnv *env;
        errno_t err = getEnv(env);
        if (err) {
            std::cerr << "[CppJsLib] Could not initialize JNIEnv. Error: " << err << std::endl;
            return;
        }

        jclass LoggingFunction = env->FindClass("Lcom/markusjx/cppjslib/interfaces/LoggingFunction;");
        jmethodID log = env->GetMethodID(LoggingFunction, "log", "(Ljava/lang/String;)V");
        jstring msg = env->NewStringUTF(s.c_str());

        env->CallVoidMethod(loggingF, log, msg);
        CHECK_JAVA_EXCEPTION();
    });
}

/*
 * Class:     markusjx_cppjslib_nt_CppJsLibNative
 * Method:    setError
 * Signature: (Lmarkusjx/cppjslib/interfaces/LoggingFunction;)V
 */
JNIEXPORT void
JNICALL Java_com_markusjx_cppjslib_nt_CppJsLibNative_setError__Lcom_markusjx_cppjslib_interfaces_LoggingFunction_2(
        JNIEnv *env, jclass, jobject errorFunction) {
    SET_JVM();
    jobject errorF = env->NewGlobalRef(errorFunction);
    if (eF)
        env->DeleteGlobalRef(eF);
    eF = errorF;

    CppJsLib::setError([errorF](const std::string &s) {
        JNIEnv *env;
        errno_t err = getEnv(env);
        if (err) {
            std::cerr << "[CppJsLib] Could not initialize JNIEnv. Error: " << err << std::endl;
            return;
        }

        jclass LoggingFunction = env->FindClass("Lcom/markusjx/cppjslib/interfaces/LoggingFunction;");
        jmethodID log = env->GetMethodID(LoggingFunction, "log", "(Ljava/lang/String;)V");
        jstring msg = env->NewStringUTF(s.c_str());

        env->CallVoidMethod(errorF, log, msg);
        CHECK_JAVA_EXCEPTION();
    });
}

/*
 * Class:     markusjx_cppjslib_nt_CppJsLibNative
 * Method:    setWebSocketOpenHandler
 * Signature: (ILmarkusjx/cppjslib/interfaces/Handler;)V
 */
JNIEXPORT void
JNICALL Java_com_markusjx_cppjslib_nt_CppJsLibNative_setWebSocketOpenHandler(JNIEnv *env, jclass, jint id,
                                                                             jobject handler) {
    SET_JVM();
    WebGUIContainer *c = findContainer(id);
    if (c) {
        jobject hdl = env->NewGlobalRef(handler);
        c->jv.push_back(hdl);

        c->webGui->setWebSocketOpenHandler([hdl]() {
            JNIEnv *env;
            errno_t err = getEnv(env);
            if (err) {
                errorF("[CppJsLib] Could not initialize JNIEnv. Error: " + std::to_string(err));
                return;
            }

            jclass Handler = env->FindClass("Lcom/markusjx/cppjslib/interfaces/Handler;");
            jmethodID call = env->GetMethodID(Handler, "call", "()V");

            env->CallVoidMethod(hdl, call);
            CHECK_JAVA_EXCEPTION();
        });
    }
}

/*
 * Class:     markusjx_cppjslib_nt_CppJsLibNative
 * Method:    setWebSocketCloseHandler
 * Signature: (ILmarkusjx/cppjslib/interfaces/Handler;)V
 */
JNIEXPORT void
JNICALL Java_com_markusjx_cppjslib_nt_CppJsLibNative_setWebSocketCloseHandler(JNIEnv *env, jclass, jint id,
                                                                              jobject handler) {
    SET_JVM();
    WebGUIContainer *c = findContainer(id);
    if (c) {
        jobject hdl = env->NewGlobalRef(handler);
        c->jv.push_back(hdl);

        c->webGui->setWebSocketCloseHandler([hdl]() {
            JNIEnv *env;
            errno_t err = getEnv(env);
            if (err) {
                errorF("[CppJsLib] Could not initialize JNIEnv. Error: " + std::to_string(err));
                return;
            }

            jclass Handler = env->FindClass("Lcom/markusjx/cppjslib/interfaces/Handler;");
            jmethodID call = env->GetMethodID(Handler, "call", "()V");

            env->CallVoidMethod(hdl, call);
            CHECK_JAVA_EXCEPTION();
        });
    }
}

/*
 * Class:     markusjx_cppjslib_nt_CppJsLibNative
 * Method:    start
 * Signature: (IIILjava/lang/String;Z)Z
 */
JNIEXPORT jboolean
JNICALL Java_com_markusjx_cppjslib_nt_CppJsLibNative_start(JNIEnv *env, jclass, jint id, jint port, jint websocketPort,
                                                           jstring host, jboolean block) {
    SET_JVM();
    WebGUIContainer *c = findContainer(id);
    if (c) {
        auto _host = env->GetStringUTFChars(host, &isFalse);
        bool res = c->webGui->start(port, websocketPort, _host, block);
        env->ReleaseStringUTFChars(host, _host);
        return res;
    } else {
        return false;
    }
}

/*
 * Class:     markusjx_cppjslib_nt_CppJsLibNative
 * Method:    startNoWeb
 * Signature: (IIZ)Z
 */
JNIEXPORT jboolean
JNICALL Java_com_markusjx_cppjslib_nt_CppJsLibNative_startNoWeb(JNIEnv *env, jclass, jint id, jint port,
                                                                jboolean block) {
    SET_JVM();
    WebGUIContainer *c = findContainer(id);
    if (c) {
        return c->webGui->startNoWeb(port, block);
    } else {
        return false;
    }
}

/*
 * Class:     com_markusjx_cppjslib_nt_CppJsLibNative
 * Method:    setMountPoint
 * Signature: (ILjava/lang/String;Ljava/lang/String;)V
 */
JNIEXPORT void
JNICALL Java_com_markusjx_cppjslib_nt_CppJsLibNative_setMountPoint(JNIEnv *env, jclass, jint id, jstring mnt,
                                                                   jstring dir) {
    SET_JVM();
    WebGUIContainer *c = findContainer(id);
    if (c) {
        auto _mnt = env->GetStringUTFChars(mnt, &isFalse);
        auto _dir = env->GetStringUTFChars(dir, &isFalse);

        c->webGui->set_mount_point(_mnt, _dir);

        env->ReleaseStringUTFChars(mnt, _mnt);
        env->ReleaseStringUTFChars(dir, _dir);
    }
}

/*
 * Class:     com_markusjx_cppjslib_nt_CppJsLibNative
 * Method:    removeMountPoint
 * Signature: (ILjava/lang/String;)V
 */
JNIEXPORT void
JNICALL Java_com_markusjx_cppjslib_nt_CppJsLibNative_removeMountPoint(JNIEnv *env, jclass, jint id, jstring mnt) {
    SET_JVM();
    WebGUIContainer *c = findContainer(id);
    if (c) {
        auto _mnt = env->GetStringUTFChars(mnt, &isFalse);
        c->webGui->remove_mount_point(_mnt);
        env->ReleaseStringUTFChars(mnt, _mnt);
    }
}

/*
 * Class:     markusjx_cppjslib_nt_CppJsLibNative
 * Method:    stop
 * Signature: (IZI)Z
 */
JNIEXPORT jboolean
JNICALL Java_com_markusjx_cppjslib_nt_CppJsLibNative_stop(JNIEnv *env, jclass, jint id, jboolean block, jint maxWait) {
    SET_JVM();
    WebGUIContainer *c = findContainer(id);
    if (c)
        return CppJsLib::util::stop(c->webGui, block, maxWait);
    else
        return false;
}

/*
 * Class:     markusjx_cppjslib_nt_CppJsLibNative
 * Method:    exposeFunction
 * Signature: (ILmarkusjx/cppjslib/interfaces/CExposedFunc;Ljava/lang/String;Ljava/lang/String;[Ljava/lang/String;)V
 */
JNIEXPORT void
JNICALL Java_com_markusjx_cppjslib_nt_CppJsLibNative_exposeFunction(JNIEnv *env, jclass, jint id, jobject func,
                                                                    jstring name, jstring returnType,
                                                                    jobjectArray argTypes) {
    SET_JVM();
    WebGUIContainer *c = findContainer(id);
    if (c) {
        std::map<const char *, jstring> m;
        const char *_name = env->GetStringUTFChars(name, &isFalse);
        m.insert(std::make_pair(_name, name));

        std::string rt = getTypeName(env->GetStringUTFChars(returnType, &isFalse));

        int len = env->GetArrayLength(argTypes);
        auto *args = new std::string[len];
        for (int i = 0; i < len; i++) {
            auto jStr = (jstring) env->GetObjectArrayElement(argTypes, i);
            const char *str = env->GetStringUTFChars(jStr, &isFalse);
            args[i] = getTypeName(str);
            m.insert(std::make_pair(str, jStr));
        }

        jobject fn = env->NewGlobalRef(func);
        c->jv.push_back(fn);

        c->webGui->exportJavaFunction(_name, rt, args, len, [rt, fn](std::string *argv, int argc) {
            JNIEnv *env;
            errno_t err = getEnv(env);
            if (err) {
                errorF("[CppJsLib] Could not initialize JNIEnv. Error: " + std::to_string(err));
                return "";
            }

            jclass ExposedFunc = env->FindClass("Lcom/markusjx/cppjslib/interfaces/CExposedFunc;");
            jmethodID call = env->GetMethodID(ExposedFunc, "call", "([Ljava/lang/String;)[Ljava/lang/String;");

            jclass String = JAVA_STRING_CLS();
            jobjectArray arr = env->NewObjectArray(argc, String, nullptr);

            for (int i = 0; i < argc; i++) {
                jstring str = env->NewStringUTF(argv[i].c_str());
                env->SetObjectArrayElement(arr, i, str);
            }

            auto res = (jstring) env->CallObjectMethod(fn, call, arr);
            CHECK_JAVA_EXCEPTION();

            return env->GetStringUTFChars(res, &isFalse);
        });
        delete[] args;
        for (std::pair<const char *, jstring> p : m) {
            env->ReleaseStringUTFChars(p.second, p.first);
        }
    }
}

/*
 * Class:     markusjx_cppjslib_nt_CppJsLibNative
 * Method:    exposeVoidFunction
 * Signature: (ILmarkusjx/cppjslib/interfaces/CExposedVoidFunc;Ljava/lang/String;[Ljava/lang/String;)V
 */
JNIEXPORT void
JNICALL Java_com_markusjx_cppjslib_nt_CppJsLibNative_exposeVoidFunction(JNIEnv *env, jclass, jint id, jobject func,
                                                                        jstring name, jobjectArray argTypes) {
    SET_JVM();
    WebGUIContainer *c = findContainer(id);
    if (c) {
        std::map<const char *, jstring> m;
        const char *_name = env->GetStringUTFChars(name, &isFalse);
        m.insert(std::make_pair(_name, name));

        int len = env->GetArrayLength(argTypes);
        auto *args = new std::string[len];
        for (int i = 0; i < len; i++) {
            auto jStr = (jstring) env->GetObjectArrayElement(argTypes, i);
            const char *str = env->GetStringUTFChars(jStr, &isFalse);
            args[i] = getTypeName(str);
            m.insert(std::make_pair(str, jStr));
        }

        jobject fn = env->NewGlobalRef(func);
        c->jv.push_back(fn);

        c->webGui->exportJavaFunction(_name, "void", args, len, [fn](std::string *argv, int argc) {
            JNIEnv *env;
            errno_t err = getEnv(env);
            if (err) {
                errorF("[CppJsLib] Could not initialize JNIEnv. Error: " + std::to_string(err));
                return "";
            }
            jclass ExposedFunc = env->FindClass("Lcom/markusjx/cppjslib/interfaces/CExposedVoidFunc;");
            jmethodID call = env->GetMethodID(ExposedFunc, "call", "([Ljava/lang/String;)V");

            jclass String = JAVA_STRING_CLS();
            jobjectArray arr = env->NewObjectArray(argc, String, nullptr);

            for (int i = 0; i < argc; i++) {
                jstring str = env->NewStringUTF(argv[i].c_str());
                env->SetObjectArrayElement(arr, i, str);
            }

            env->CallVoidMethod(fn, call, arr);
            CHECK_JAVA_EXCEPTION();

            return "";
        });
        delete[] args;

        for (std::pair<const char *, jstring> p : m) {
            env->ReleaseStringUTFChars(p.second, p.first);
        }
    }
}

/*
 * Class:     markusjx_cppjslib_nt_CppJsLibNative
 * Method:    importFunction
 * Signature: (ILjava/lang/String;Ljava/lang/String;[Ljava/lang/String;)I
 */
JNIEXPORT jint
JNICALL Java_com_markusjx_cppjslib_nt_CppJsLibNative_importFunction(JNIEnv *env, jclass, jint id, jstring name,
                                                                    jstring returnType, jobjectArray argTypes,
                                                                    jint wait) {
    SET_JVM();
    WebGUIContainer *c = findContainer(id);
    int res = -1;
    if (c) {
        std::map<const char *, jstring> m;
        const char *n = env->GetStringUTFChars(name, &isFalse);
        m.insert(std::make_pair(n, name));

        string rt = getTypeName(env->GetStringUTFChars(returnType, &isFalse));
        int len = env->GetArrayLength(argTypes);
        auto args = new std::string[len];

        for (int i = 0; i < len; i++) {
            auto jStr = (jstring) env->GetObjectArrayElement(argTypes, i);
            const char *str = env->GetStringUTFChars(jStr, &isFalse);
            args[i] = getTypeName(str);
            m.insert(std::make_pair(str, jStr));
        }

        if (rt == "void") {
            res = c->insertVoidJsFunction(n, args, len);
        } else {
            res = c->insertJsFunction(n, rt, args, len, wait);
        }
        delete[] args;

        for (std::pair<const char *, jstring> p : m) {
            env->ReleaseStringUTFChars(p.second, p.first);
        }
    }

    return res;
}

/*
 * Class:     markusjx_cppjslib_nt_CppJsLibNative
 * Method:    callJSFunction
 * Signature: (II[Ljava/lang/Object;)Ljava/lang/Object;
 */
JNIEXPORT jobjectArray
JNICALL Java_com_markusjx_cppjslib_nt_CppJsLibNative_callJSFunction(JNIEnv *env, jclass, jint clsID, jint id,
                                                                    jobjectArray args) {
    SET_JVM();
    jclass String = JAVA_STRING_CLS();
    WebGUIContainer *c = findContainer(id);
    if (c) {
        int len = env->GetArrayLength(args);
        auto ar = new std::string[len];
        std::map<const char *, jstring> m;
        for (int i = 0; i < len; i++) {
            auto jStr = (jstring) env->GetObjectArrayElement(args, i);
            const char *str = env->GetStringUTFChars(jStr, &isFalse);

            ar[i] = str;
            m.insert(std::make_pair(str, jStr));
        }

        vector<string> res = (*(J_JsFunction *) c->v[clsID])(ar);
        delete[] ar;
        for (std::pair<const char *, jstring> p : m) {
            env->ReleaseStringUTFChars(p.second, p.first);
        }

        jobjectArray tmp = env->NewObjectArray((jsize) res.size(), String, nullptr);
        for (int i = 0; i < res.size(); i++) {
            env->SetObjectArrayElement(tmp, i, env->NewStringUTF(res[i].c_str()));
        }

        return tmp;
    } else {
        return env->NewObjectArray(0, String, nullptr);
    }
}

/*
 * Class:     markusjx_cppjslib_nt_CppJsLibNative
 * Method:    callVoidJsFunction
 * Signature: (II[Ljava/lang/String;)V
 */
JNIEXPORT void
JNICALL Java_com_markusjx_cppjslib_nt_CppJsLibNative_callVoidJsFunction(JNIEnv *env, jclass, jint clsID, jint id,
                                                                        jobjectArray args) {
    SET_JVM();
    WebGUIContainer *c = findContainer(id);
    if (c) {
        int len = env->GetArrayLength(args);
        auto ar = new std::string[len];
        std::map<const char *, jstring> m;

        for (int i = 0; i < len; i++) {
            auto jStr = (jstring) env->GetObjectArrayElement(args, i);
            const char *str = env->GetStringUTFChars(jStr, &isFalse);

            ar[i] = str;
            m.insert(std::make_pair(str, jStr));
        }

        (*(J_VoidJsFunction *) c->v[clsID])(ar);
        delete[] ar;

        for (std::pair<const char *, jstring> p : m) {
            env->ReleaseStringUTFChars(p.second, p.first);
        }
    }
}

/*
 * Class:     markusjx_cppjslib_nt_CppJsLibNative
 * Method:    stringArrayToJSON
 * Signature: ([Ljava/lang/String;)Ljava/lang/String;
 */
JNIEXPORT jstring
JNICALL Java_com_markusjx_cppjslib_nt_CppJsLibNative_stringArrayToJSON(JNIEnv *env, jclass, jobjectArray arr) {
    SET_JVM();
    jsize len = env->GetArrayLength(arr);
    vector<string> v;
    std::map<const char *, jstring> m;

    for (int i = 0; i < len; i++) {
        auto str = (jstring) env->GetObjectArrayElement(arr, i);
        const char *c = env->GetStringUTFChars(str, &isFalse);
        v.emplace_back(c);
        m.insert(std::make_pair(c, str));
    }

    string res = CppJsLib::util::stringArrayToJSON(&v);
    for (std::pair<const char *, jstring> p : m) {
        env->ReleaseStringUTFChars(p.second, p.first);
    }

    return env->NewStringUTF(res.c_str());
}

/*
 * Class:     markusjx_cppjslib_nt_CppJsLibNative
 * Method:    createStringArrayFromJSON
 * Signature: (Ljava/lang/String;)[Ljava/lang/String;
 */
JNIEXPORT jobjectArray
JNICALL Java_com_markusjx_cppjslib_nt_CppJsLibNative_createStringArrayFromJSON(JNIEnv *env, jclass, jstring json) {
    SET_JVM();
    const char *s = env->GetStringUTFChars(json, &isFalse);

    int size = 0;
    string *res = CppJsLib::util::createStringArrayFromJSON(&size, s);
    env->ReleaseStringUTFChars(json, s);

    jclass String = JAVA_STRING_CLS();
    jobjectArray arr = env->NewObjectArray(size, String, nullptr);

    for (int i = 0; i < size; i++) {
        jstring str = env->NewStringUTF(res[i].c_str());
        env->SetObjectArrayElement(arr, i, str);
    }

    return arr;
}

/*
 * Class:     markusjx_cppjslib_nt_CppJsLibNative
 * Method:    deleteWebGUI
 * Signature: (I)V
 */
JNIEXPORT void JNICALL Java_com_markusjx_cppjslib_nt_CppJsLibNative_deleteWebGUI(JNIEnv *env, jclass, jint id) {
    SET_JVM();
    for (auto it = instances.begin(); it != instances.end(); ++it) {
        if ((*it)->id == id) {
            delete (*it);
            instances.erase(it);
            break;
        }
    }
}

/*
 * Class:     markusjx_cppjslib_nt_CppJsLibNative
 * Method:    ok
 * Signature: ()Z
 */
JNIEXPORT jboolean JNICALL Java_com_markusjx_cppjslib_nt_CppJsLibNative_ok(JNIEnv *env, jclass) {
    SET_JVM();
    return CppJsLib::ok();
}

/*
 * Class:     markusjx_cppjslib_nt_CppJsLibNative
 * Method:    getLastError
 * Signature: ()Ljava/lang/String;
 */
JNIEXPORT jstring JNICALL Java_com_markusjx_cppjslib_nt_CppJsLibNative_getLastError(JNIEnv *env, jclass) {
    SET_JVM();
    return env->NewStringUTF(CppJsLib::getLastError().c_str());
}

/*
 * Class:     markusjx_cppjslib_nt_CppJsLibNative
 * Method:    resetLastError
 * Signature: ()V
 */
JNIEXPORT void JNICALL Java_com_markusjx_cppjslib_nt_CppJsLibNative_resetLastError(JNIEnv *env, jclass) {
    SET_JVM();
    CppJsLib::resetLastError();
}
