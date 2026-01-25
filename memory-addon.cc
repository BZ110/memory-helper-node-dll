#include <napi.h>
#include <windows.h>

// ---- DLL typedefs -------------------------------------------------------

typedef HANDLE (*OpenProcessForNodeFunc)(DWORD);
typedef BOOL   (*ReadMemoryForNodeFunc)(HANDLE, LPCVOID, LPVOID, SIZE_T, SIZE_T*);
typedef BOOL   (*CloseHandleForNodeFunc)(HANDLE);
typedef DWORD  (*FindPidsByExeNameAFunc)(const char*, DWORD*, DWORD, BOOL);
typedef DWORD  (*FindServicePidAFunc)(const char*);
typedef void   (*ScanCallback)(UINT64,const char*,const char*);

typedef struct {
    UINT64 start;
    UINT64 end;
    UINT32 minLen;
    BOOL   ascii;
    BOOL   utf16;
    BOOL   caseSensitive;
    const char *contains;
    SIZE_T maxResults;
} ScanStringOptions;

typedef DWORD (*ScanStringsForNodeFunc)(HANDLE, ScanStringOptions*, ScanCallback);

// ---- Globals ------------------------------------------------------------

static HMODULE gDLL           = NULL;
static OpenProcessForNodeFunc  pOpenProcess = NULL;
static ReadMemoryForNodeFunc   pReadMemory  = NULL;
static CloseHandleForNodeFunc  pCloseHandle = NULL;
static FindPidsByExeNameAFunc  pFindPids    = NULL;
static FindServicePidAFunc     pFindService = NULL;
static ScanStringsForNodeFunc  pScanStrings = NULL;

// ---- JS result buffer for scanStrings ----------------------------------

static Napi::Env*   gEnv = nullptr;
static Napi::Array* gArr = nullptr;
static uint32_t     gIdx = 0;

static void BridgeScanHit(UINT64 addr, const char* text, const char* encoding) {
    // Called synchronously from ScanStringsForNode on the same thread
    if (!gEnv || !gArr) return;

    Napi::Object o = Napi::Object::New(*gEnv);
    o.Set("address", Napi::BigInt::New(*gEnv, addr));
    o.Set("text",    Napi::String::New(*gEnv, text ? text : ""));
    o.Set("encoding",Napi::String::New(*gEnv, encoding ? encoding : "ascii"));
    gArr->Set(gIdx++, o);
}

// ---- Helper: guard that DLL and function pointers exist ----------------

static void EnsureLoadedOrThrow(const Napi::Env& env) {
    if (!gDLL) {
        Napi::Error::New(env,
            "memory-helper.dll failed to load. Make sure it is in the same "
            "folder as memory.node or in PATH.")
            .ThrowAsJavaScriptException();
        return;
    }

    if (!pOpenProcess || !pReadMemory || !pCloseHandle || !pFindPids ||
        !pFindService || !pScanStrings) {
        Napi::Error::New(env,
            "memory-helper.dll is loaded but required exports are missing. "
            "Check that it was built with the correct functions (OpenProcessForNode, "
            "ReadMemoryForNode, CloseHandleForNode, FindPidsByExeNameA, "
            "FindServicePidA, ScanStringsForNode).")
            .ThrowAsJavaScriptException();
        return;
    }
}

// ---- openProcess(pid:number) -> bigint ---------------------------------

Napi::Value OpenProcessWrapped(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    EnsureLoadedOrThrow(env);
    if (env.IsExceptionPending()) return env.Null();

    if (info.Length() < 1 || !info[0].IsNumber())
        return env.Null();

    DWORD pid = info[0].As<Napi::Number>().Uint32Value();
    HANDLE h = pOpenProcess(pid);

    return Napi::BigInt::New(env, (uint64_t)(uintptr_t)h);
}

// ---- closeHandle(handle:bigint) -> boolean ------------------------------

Napi::Value CloseHandleWrapped(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    EnsureLoadedOrThrow(env);
    if (env.IsExceptionPending()) return env.Null();

    if (info.Length() < 1 || !info[0].IsBigInt())
        return Napi::Boolean::New(env, false);

    bool loss = false;
    uint64_t hv = info[0].As<Napi::BigInt>().Uint64Value(&loss);
    HANDLE h = (HANDLE)(uintptr_t)hv;

    if (!h) return Napi::Boolean::New(env, false);

    BOOL ok = pCloseHandle(h);
    return Napi::Boolean::New(env, ok ? true : false);
}

// ---- readMemory(handle, addr, size) -> Buffer|null ----------------------

Napi::Value ReadMemoryWrapped(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    EnsureLoadedOrThrow(env);
    if (env.IsExceptionPending()) return env.Null();

    if (info.Length() < 3 ||
        !info[0].IsBigInt() ||
        !info[1].IsBigInt() ||
        !info[2].IsNumber()) {
        return env.Null();
    }

    bool l1 = false, l2 = false;
    uint64_t hv   = info[0].As<Napi::BigInt>().Uint64Value(&l1);
    uint64_t addr = info[1].As<Napi::BigInt>().Uint64Value(&l2);
    SIZE_T size   = (SIZE_T)info[2].As<Napi::Number>().Uint32Value();

    if (!hv || !addr || size == 0)
        return env.Null();

    char *buf = (char*)malloc(size);
    if (!buf) return env.Null();

    SIZE_T br = 0;
    BOOL ok = pReadMemory((HANDLE)(uintptr_t)hv, (LPCVOID)(uintptr_t)addr, buf, size, &br);

    if (!ok || br == 0) {
        free(buf);
        return env.Null();
    }

    Napi::Buffer<char> out = Napi::Buffer<char>::Copy(env, buf, (size_t)br);
    free(buf);
    return out;
}

// ---- findPidsByExeName(name:string) -> number[] -------------------------

Napi::Value FindPidsWrapped(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    EnsureLoadedOrThrow(env);
    if (env.IsExceptionPending()) return env.Null();

    if (info.Length() < 1 || !info[0].IsString())
        return Napi::Array::New(env, 0);

    std::string exe = info[0].As<Napi::String>().Utf8Value();

    DWORD arr[256] = {0};
    DWORD hits = pFindPids(exe.c_str(), arr, 256, TRUE);

    Napi::Array out = Napi::Array::New(env, hits);
    for (DWORD i = 0; i < hits; i++) {
        out.Set(i, Napi::Number::New(env, arr[i]));
    }

    return out;
}

// ---- findServicePid(name:string) -> number ------------------------------

Napi::Value FindServiceWrapped(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    EnsureLoadedOrThrow(env);
    if (env.IsExceptionPending()) return env.Null();

    if (info.Length() < 1 || !info[0].IsString())
        return Napi::Number::New(env, 0);

    std::string svc = info[0].As<Napi::String>().Utf8Value();
    DWORD pid = pFindService(svc.c_str());
    return Napi::Number::New(env, pid);
}

// ---- scanStrings(handle, options?) -> hit[] ----------------------------

Napi::Value ScanStringsWrapped(const Napi::CallbackInfo& info) {
    Napi::Env env = info.Env();
    EnsureLoadedOrThrow(env);
    if (env.IsExceptionPending()) return env.Null();

    if (info.Length() < 1 || !info[0].IsBigInt()) {
        return Napi::Array::New(env, 0);
    }

    bool loss = false;
    uint64_t hv = info[0].As<Napi::BigInt>().Uint64Value(&loss);
    HANDLE h = (HANDLE)(uintptr_t)hv;
    if (!h) return Napi::Array::New(env, 0);

    ScanStringOptions opt;
    opt.start         = 0;
    opt.end           = 0x7fffffffffffULL;
    opt.minLen        = 4;
    opt.ascii         = TRUE;
    opt.utf16         = TRUE;
    opt.caseSensitive = FALSE;
    opt.contains      = NULL;
    opt.maxResults    = 1024;

    // Keep 'contains' alive while scan runs
    std::string containsStr;

    if (info.Length() > 1 && info[1].IsObject()) {
        Napi::Object o = info[1].As<Napi::Object>();

        if (o.Has("start") && o.Get("start").IsBigInt()) {
            bool l = false;
            uint64_t s = o.Get("start").As<Napi::BigInt>().Uint64Value(&l);
            opt.start = s;
        }
        if (o.Has("end") && o.Get("end").IsBigInt()) {
            bool l = false;
            uint64_t e = o.Get("end").As<Napi::BigInt>().Uint64Value(&l);
            opt.end = e;
        }

        if (o.Has("contains") && o.Get("contains").IsString()) {
            containsStr = o.Get("contains").As<Napi::String>().Utf8Value();
            if (!containsStr.empty()) {
                opt.contains = containsStr.c_str();
            }
        }
        if (o.Has("minLength")) {
            opt.minLen = o.Get("minLength").As<Napi::Number>().Uint32Value();
        }
        if (o.Has("ascii")) {
            opt.ascii = o.Get("ascii").As<Napi::Boolean>().Value() ? TRUE : FALSE;
        }
        if (o.Has("utf16")) {
            opt.utf16 = o.Get("utf16").As<Napi::Boolean>().Value() ? TRUE : FALSE;
        }
        if (o.Has("caseSensitive")) {
            opt.caseSensitive = o.Get("caseSensitive").As<Napi::Boolean>().Value() ? TRUE : FALSE;
        }
        if (o.Has("maxResults")) {
            opt.maxResults = (SIZE_T)o.Get("maxResults").As<Napi::Number>().Uint32Value();
        }
    }

    Napi::Array arr = Napi::Array::New(env);
    gEnv = &env;
    gArr = &arr;
    gIdx = 0;

    if (pScanStrings) {
        pScanStrings(h, &opt, BridgeScanHit);
    }

    // Clear globals
    gEnv = nullptr;
    gArr = nullptr;

    return arr;
}

// ---- Init ---------------------------------------------------------------

Napi::Object Init(Napi::Env env, Napi::Object exports) {
    // Load the helper DLL from the same directory (or PATH)
    gDLL = LoadLibraryA("memory-helper.dll");
    if (!gDLL) {
        // Don't throw here; allow JS to require() successfully and fail lazily
        // so it's easier to diagnose (we throw when a function is actually used).
    } else {
        pOpenProcess = (OpenProcessForNodeFunc) GetProcAddress(gDLL, "OpenProcessForNode");
        pReadMemory  = (ReadMemoryForNodeFunc)  GetProcAddress(gDLL, "ReadMemoryForNode");
        pCloseHandle = (CloseHandleForNodeFunc) GetProcAddress(gDLL, "CloseHandleForNode");
        pFindPids    = (FindPidsByExeNameAFunc) GetProcAddress(gDLL, "FindPidsByExeNameA");
        pFindService = (FindServicePidAFunc)    GetProcAddress(gDLL, "FindServicePidA");
        pScanStrings = (ScanStringsForNodeFunc) GetProcAddress(gDLL, "ScanStringsForNode");
    }

    exports.Set("openProcess",       Napi::Function::New(env, OpenProcessWrapped));
    exports.Set("closeHandle",       Napi::Function::New(env, CloseHandleWrapped));
    exports.Set("readMemory",        Napi::Function::New(env, ReadMemoryWrapped));
    exports.Set("findPidsByExeName", Napi::Function::New(env, FindPidsWrapped));
    exports.Set("findServicePid",    Napi::Function::New(env, FindServiceWrapped));
    exports.Set("scanStrings",       Napi::Function::New(env, ScanStringsWrapped));

    return exports;
}

NODE_API_MODULE(memory, Init);
