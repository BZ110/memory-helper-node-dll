#include <napi.h>
#include <windows.h>

#include <cstdint>
#include <cstdlib>
#include <string>

using OpenProcessFn = HANDLE (*)(DWORD);
using ReadMemoryFn = BOOL (*)(HANDLE, LPCVOID, LPVOID, SIZE_T, SIZE_T *);
using CloseHandleFn = BOOL (*)(HANDLE);
using FindPidsFn = DWORD (*)(const char *, DWORD *, DWORD, BOOL);
using FindServicePidFn = DWORD (*)(const char *);
using ScanCallback = void (*)(UINT64, const char *, const char *);

struct ScanStringOptions {
    UINT64 start;
    UINT64 end;
    UINT32 minLen;
    BOOL ascii;
    BOOL utf16;
    BOOL caseSensitive;
    const char *contains;
    SIZE_T maxResults;
};

using ScanStringsFn = DWORD (*)(HANDLE, ScanStringOptions *, ScanCallback);

static HMODULE helperDll = nullptr;
static OpenProcessFn openProcessFn = nullptr;
static ReadMemoryFn readMemoryFn = nullptr;
static CloseHandleFn closeHandleFn = nullptr;
static FindPidsFn findPidsFn = nullptr;
static FindServicePidFn findServicePidFn = nullptr;
static ScanStringsFn scanStringsFn = nullptr;

/* scanStrings is synchronous, so a small bridge like this is enough here. */
static Napi::Env *scanEnv = nullptr;
static Napi::Array *scanResults = nullptr;
static uint32_t scanResultIndex = 0;

static void onScanResult(UINT64 address,
                         const char *text,
                         const char *encoding)
{
    if (!scanEnv || !scanResults)
        return;

    Napi::Object hit = Napi::Object::New(*scanEnv);
    hit.Set("address", Napi::BigInt::New(*scanEnv, address));
    hit.Set("text", Napi::String::New(*scanEnv, text ? text : ""));
    hit.Set("encoding", Napi::String::New(*scanEnv,
                                           encoding ? encoding : "ascii"));

    scanResults->Set(scanResultIndex++, hit);
}

static bool checkHelperLoaded(Napi::Env env)
{
    if (!helperDll) {
        Napi::Error::New(
            env,
            "Could not load memory-helper.dll. Put it next to memory.node "
            "or make sure its directory is in PATH."
        ).ThrowAsJavaScriptException();
        return false;
    }

    if (!openProcessFn || !readMemoryFn || !closeHandleFn ||
        !findPidsFn || !findServicePidFn || !scanStringsFn) {
        Napi::Error::New(
            env,
            "memory-helper.dll loaded, but one or more required exports "
            "could not be found."
        ).ThrowAsJavaScriptException();
        return false;
    }

    return true;
}

static Napi::Value openProcess(const Napi::CallbackInfo &info)
{
    Napi::Env env = info.Env();
    if (!checkHelperLoaded(env))
        return env.Null();

    if (info.Length() < 1 || !info[0].IsNumber())
        return env.Null();

    DWORD pid = info[0].As<Napi::Number>().Uint32Value();
    HANDLE handle = openProcessFn(pid);

    return Napi::BigInt::New(env,
                             static_cast<uint64_t>(
                                 reinterpret_cast<uintptr_t>(handle)));
}

static Napi::Value closeHandle(const Napi::CallbackInfo &info)
{
    Napi::Env env = info.Env();
    if (!checkHelperLoaded(env))
        return env.Null();

    if (info.Length() < 1 || !info[0].IsBigInt())
        return Napi::Boolean::New(env, false);

    bool lossless = false;
    uint64_t rawHandle = info[0].As<Napi::BigInt>().Uint64Value(&lossless);
    HANDLE handle = reinterpret_cast<HANDLE>(static_cast<uintptr_t>(rawHandle));

    if (!handle)
        return Napi::Boolean::New(env, false);

    return Napi::Boolean::New(env, closeHandleFn(handle) != FALSE);
}

static Napi::Value readMemory(const Napi::CallbackInfo &info)
{
    Napi::Env env = info.Env();
    if (!checkHelperLoaded(env))
        return env.Null();

    if (info.Length() < 3 ||
        !info[0].IsBigInt() ||
        !info[1].IsBigInt() ||
        !info[2].IsNumber()) {
        return env.Null();
    }

    bool handleLossless = false;
    bool addressLossless = false;

    uint64_t rawHandle = info[0].As<Napi::BigInt>().Uint64Value(&handleLossless);
    uint64_t rawAddress = info[1].As<Napi::BigInt>().Uint64Value(&addressLossless);
    SIZE_T requested = static_cast<SIZE_T>(
        info[2].As<Napi::Number>().Uint32Value());

    if (!rawHandle || !rawAddress || requested == 0)
        return env.Null();

    char *buffer = static_cast<char *>(std::malloc(requested));
    if (!buffer)
        return env.Null();

    SIZE_T bytesRead = 0;
    BOOL ok = readMemoryFn(
        reinterpret_cast<HANDLE>(static_cast<uintptr_t>(rawHandle)),
        reinterpret_cast<LPCVOID>(static_cast<uintptr_t>(rawAddress)),
        buffer,
        requested,
        &bytesRead
    );

    if (!ok || bytesRead == 0) {
        std::free(buffer);
        return env.Null();
    }

    auto result = Napi::Buffer<char>::Copy(env, buffer, bytesRead);
    std::free(buffer);
    return result;
}

static Napi::Value findPidsByExeName(const Napi::CallbackInfo &info)
{
    Napi::Env env = info.Env();
    if (!checkHelperLoaded(env))
        return env.Null();

    if (info.Length() < 1 || !info[0].IsString())
        return Napi::Array::New(env);

    std::string exeName = info[0].As<Napi::String>().Utf8Value();

    DWORD pids[256] = {0};
    DWORD found = findPidsFn(exeName.c_str(), pids, 256, TRUE);
    DWORD returned = found < 256 ? found : 256;

    Napi::Array result = Napi::Array::New(env, returned);
    for (DWORD i = 0; i < returned; ++i)
        result.Set(i, Napi::Number::New(env, pids[i]));

    return result;
}

static Napi::Value findServicePid(const Napi::CallbackInfo &info)
{
    Napi::Env env = info.Env();
    if (!checkHelperLoaded(env))
        return env.Null();

    if (info.Length() < 1 || !info[0].IsString())
        return Napi::Number::New(env, 0);

    std::string serviceName = info[0].As<Napi::String>().Utf8Value();
    return Napi::Number::New(env, findServicePidFn(serviceName.c_str()));
}

static Napi::Value scanStrings(const Napi::CallbackInfo &info)
{
    Napi::Env env = info.Env();
    if (!checkHelperLoaded(env))
        return env.Null();

    if (info.Length() < 1 || !info[0].IsBigInt())
        return Napi::Array::New(env);

    bool lossless = false;
    uint64_t rawHandle = info[0].As<Napi::BigInt>().Uint64Value(&lossless);
    HANDLE handle = reinterpret_cast<HANDLE>(static_cast<uintptr_t>(rawHandle));

    if (!handle)
        return Napi::Array::New(env);

    ScanStringOptions options{};
    options.start = 0;
    options.end = 0x7fffffffffffULL;
    options.minLen = 4;
    options.ascii = TRUE;
    options.utf16 = TRUE;
    options.caseSensitive = FALSE;
    options.contains = nullptr;
    options.maxResults = 1024;

    std::string contains;

    if (info.Length() > 1 && info[1].IsObject()) {
        Napi::Object input = info[1].As<Napi::Object>();

        if (input.Has("start") && input.Get("start").IsBigInt()) {
            bool ignored = false;
            options.start = input.Get("start")
                                .As<Napi::BigInt>()
                                .Uint64Value(&ignored);
        }

        if (input.Has("end") && input.Get("end").IsBigInt()) {
            bool ignored = false;
            options.end = input.Get("end")
                              .As<Napi::BigInt>()
                              .Uint64Value(&ignored);
        }

        if (input.Has("contains") && input.Get("contains").IsString()) {
            contains = input.Get("contains").As<Napi::String>().Utf8Value();
            if (!contains.empty())
                options.contains = contains.c_str();
        }

        if (input.Has("minLength") && input.Get("minLength").IsNumber())
            options.minLen = input.Get("minLength").As<Napi::Number>().Uint32Value();

        if (input.Has("ascii") && input.Get("ascii").IsBoolean())
            options.ascii = input.Get("ascii").As<Napi::Boolean>().Value() ? TRUE : FALSE;

        if (input.Has("utf16") && input.Get("utf16").IsBoolean())
            options.utf16 = input.Get("utf16").As<Napi::Boolean>().Value() ? TRUE : FALSE;

        if (input.Has("caseSensitive") && input.Get("caseSensitive").IsBoolean())
            options.caseSensitive = input.Get("caseSensitive")
                                        .As<Napi::Boolean>()
                                        .Value() ? TRUE : FALSE;

        if (input.Has("maxResults") && input.Get("maxResults").IsNumber())
            options.maxResults = static_cast<SIZE_T>(
                input.Get("maxResults").As<Napi::Number>().Uint32Value());
    }

    Napi::Array results = Napi::Array::New(env);

    scanEnv = &env;
    scanResults = &results;
    scanResultIndex = 0;

    scanStringsFn(handle, &options, onScanResult);

    scanEnv = nullptr;
    scanResults = nullptr;
    scanResultIndex = 0;

    return results;
}

static Napi::Object init(Napi::Env env, Napi::Object exports)
{
    helperDll = LoadLibraryA("memory-helper.dll");

    if (helperDll) {
        openProcessFn = reinterpret_cast<OpenProcessFn>(
            GetProcAddress(helperDll, "OpenProcessForNode"));
        readMemoryFn = reinterpret_cast<ReadMemoryFn>(
            GetProcAddress(helperDll, "ReadMemoryForNode"));
        closeHandleFn = reinterpret_cast<CloseHandleFn>(
            GetProcAddress(helperDll, "CloseHandleForNode"));
        findPidsFn = reinterpret_cast<FindPidsFn>(
            GetProcAddress(helperDll, "FindPidsByExeNameA"));
        findServicePidFn = reinterpret_cast<FindServicePidFn>(
            GetProcAddress(helperDll, "FindServicePidA"));
        scanStringsFn = reinterpret_cast<ScanStringsFn>(
            GetProcAddress(helperDll, "ScanStringsForNode"));
    }

    exports.Set("openProcess", Napi::Function::New(env, openProcess));
    exports.Set("closeHandle", Napi::Function::New(env, closeHandle));
    exports.Set("readMemory", Napi::Function::New(env, readMemory));
    exports.Set("findPidsByExeName", Napi::Function::New(env, findPidsByExeName));
    exports.Set("findServicePid", Napi::Function::New(env, findServicePid));
    exports.Set("scanStrings", Napi::Function::New(env, scanStrings));

    return exports;
}

NODE_API_MODULE(memory, init)
