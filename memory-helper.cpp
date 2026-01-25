#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <tlhelp32.h>
#include <winsvc.h>
#include <stdio.h>
#include <string.h>

// ============================================================
// Shared types (must match memory.cc)
// ============================================================
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

typedef void (*ScanCallback)(UINT64 addr, const char *text, const char *encoding);

#ifdef __cplusplus
extern "C" {
#endif

// ============================================================
// Enable SeDebugPrivilege (DFIR standard for scanning)
// ============================================================
static void EnableDebugPrivilegeOnce(void) {
    static int done = 0;
    if (done) return;
    done = 1;

    HANDLE hToken = NULL;
    if (!OpenProcessToken(GetCurrentProcess(),
                          TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
                          &hToken)) {
        return;
    }

    LUID luid;
    if (!LookupPrivilegeValueA(NULL, "SeDebugPrivilege", &luid)) {
        CloseHandle(hToken);
        return;
    }

    TOKEN_PRIVILEGES tp;
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);
    CloseHandle(hToken);
}

// ============================================================
// EXPORT: OpenProcessForNode
// ============================================================
__declspec(dllexport)
HANDLE OpenProcessForNode(DWORD pid) {
    EnableDebugPrivilegeOnce();

    HANDLE h = OpenProcess(
        PROCESS_QUERY_INFORMATION |
        PROCESS_VM_READ |
        PROCESS_VM_OPERATION |
        PROCESS_QUERY_LIMITED_INFORMATION,
        FALSE,
        pid
    );

    return h;
}

// ============================================================
// EXPORT: CloseHandleForNode
// ============================================================
__declspec(dllexport)
BOOL CloseHandleForNode(HANDLE h) {
    if (!h) return FALSE;
    return CloseHandle(h);
}

// ============================================================
// EXPORT: ReadMemoryForNode
// ============================================================
__declspec(dllexport)
BOOL ReadMemoryForNode(
    HANDLE hProcess,
    LPCVOID addr,
    LPVOID buf,
    SIZE_T size,
    SIZE_T *lpBytesRead
) {
    if (!hProcess || !addr || !buf || !lpBytesRead) return FALSE;
    return ReadProcessMemory(hProcess, addr, buf, size, lpBytesRead);
}

// ============================================================
// EXPORT: FindPidsByExeNameA
// ============================================================
__declspec(dllexport)
DWORD FindPidsByExeNameA(
    const char *exeName,
    DWORD *outPids,
    DWORD maxCount,
    BOOL caseInsensitive
) {
    if (!exeName || !outPids || maxCount == 0)
        return 0;

    EnableDebugPrivilegeOnce();

    wchar_t wExe[260];
    MultiByteToWideChar(CP_UTF8, 0, exeName, -1, wExe, 260);

    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE)
        return 0;

    PROCESSENTRY32W pe;
    pe.dwSize = sizeof(pe);

    DWORD matches = 0;
    if (Process32FirstW(snap, &pe)) {
        do {
            BOOL match;
            if (caseInsensitive)
                match = (_wcsicmp(pe.szExeFile, wExe) == 0);
            else
                match = (wcscmp(pe.szExeFile, wExe) == 0);

            if (match) {
                if (matches < maxCount)
                    outPids[matches] = pe.th32ProcessID;
                matches++;
            }
        } while (Process32NextW(snap, &pe));
    }

    CloseHandle(snap);
    return matches;
}

// ============================================================
// EXPORT: FindServicePidA
// ============================================================
__declspec(dllexport)
DWORD FindServicePidA(const char *serviceName) {
    if (!serviceName) return 0;

    EnableDebugPrivilegeOnce();

    wchar_t wName[256];
    MultiByteToWideChar(CP_UTF8, 0, serviceName, -1, wName, 256);

    SC_HANDLE scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
    if (!scm) return 0;

    SC_HANDLE svc = OpenServiceW(scm, wName, SERVICE_QUERY_STATUS);
    if (!svc) {
        CloseServiceHandle(scm);
        return 0;
    }

    SERVICE_STATUS_PROCESS ssp;
    DWORD bytes = 0;

    DWORD pid = 0;
    if (QueryServiceStatusEx(svc,
                             SC_STATUS_PROCESS_INFO,
                             (LPBYTE)&ssp,
                             sizeof(ssp),
                             &bytes)) {
        pid = ssp.dwProcessId;
    }

    CloseServiceHandle(svc);
    CloseServiceHandle(scm);

    return pid;
}

// ============================================================
// Helper: check substring (case-sensitive or insensitive)
// ============================================================
static BOOL ContainsSubstring(const char *haystack,
                              const char *needle,
                              BOOL caseSensitive) {
    if (!needle || !*needle) return TRUE;
    if (!haystack) return FALSE;

    if (caseSensitive) {
        return strstr(haystack, needle) != NULL;
    }

    // case-insensitive: naive implementation
    size_t hlen = strlen(haystack);
    size_t nlen = strlen(needle);
    if (nlen == 0) return TRUE;
    if (nlen > hlen) return FALSE;

    for (size_t i = 0; i + nlen <= hlen; ++i) {
        size_t j = 0;
        for (; j < nlen; ++j) {
            char c1 = haystack[i + j];
            char c2 = needle[j];
            if (c1 >= 'A' && c1 <= 'Z') c1 = (char)(c1 - 'A' + 'a');
            if (c2 >= 'A' && c2 <= 'Z') c2 = (char)(c2 - 'A' + 'a');
            if (c1 != c2) break;
        }
        if (j == nlen) return TRUE;
    }
    return FALSE;
}

// ============================================================
// EXPORT: ScanStringsForNode (ASCII scanning)
//   NOTE: UTF-16 scanning is not implemented here yet; 'utf16'
//   option is currently ignored and everything is treated as ASCII.
// ============================================================
__declspec(dllexport)
DWORD ScanStringsForNode(
    HANDLE hProc,
    ScanStringOptions *opt,
    ScanCallback cb
) {
    if (!hProc || !opt || !cb) return 0;

    EnableDebugPrivilegeOnce();

    UINT64 current = opt->start;
    UINT64 end     = (opt->end == 0 ? 0x7fffffffffffULL : opt->end);

    DWORD hits = 0;

    while (current < end && hits < opt->maxResults) {
        MEMORY_BASIC_INFORMATION mbi;
        SIZE_T res = VirtualQueryEx(
            hProc,
            (LPCVOID)(UINT_PTR)current,
            &mbi,
            sizeof(mbi)
        );
        if (!res) break;

        UINT64 base = (UINT64)(UINT_PTR)mbi.BaseAddress;
        UINT64 size = (UINT64)mbi.RegionSize;
        current = base + size;

        if (mbi.State != MEM_COMMIT) continue;
        if (mbi.Protect & PAGE_NOACCESS) continue;
        if (mbi.Protect & PAGE_GUARD) continue;
        if (size == 0) continue;

        // Clamp size to something reasonable to avoid giant allocations
        const UINT64 MAX_CHUNK = 16 * 1024 * 1024; // 16 MB
        if (size > MAX_CHUNK) size = MAX_CHUNK;

        void *buffer = malloc((SIZE_T)size);
        if (!buffer) continue;

        SIZE_T br = 0;
        if (!ReadProcessMemory(hProc,
                               (LPCVOID)(UINT_PTR)base,
                               buffer,
                               (SIZE_T)size,
                               &br) || br == 0) {
            free(buffer);
            continue;
        }

        char *p = (char *)buffer;
        SIZE_T i = 0;

        while (i < br && hits < opt->maxResults) {
            if (opt->ascii) {
                SIZE_T s = i;
                // printable ASCII range
                while (s < br && p[s] >= 0x20 && p[s] <= 0x7E) s++;

                SIZE_T len = s - i;
                if (len >= opt->minLen) {
                    char tmp[512];
                    SIZE_T copyLen = (len < (SIZE_T)511 ? len : (SIZE_T)511);
                    memcpy(tmp, &p[i], copyLen);
                    tmp[copyLen] = 0;

                    if (ContainsSubstring(tmp, opt->contains, opt->caseSensitive)) {
                        cb(base + i, tmp, "ascii");
                        hits++;
                    }
                }
                i = s + 1;
            } else {
                i++;
            }
        }

        free(buffer);
    }

    return hits;
}

#ifdef __cplusplus
}
#endif
