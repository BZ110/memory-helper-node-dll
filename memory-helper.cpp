#define _CRT_SECURE_NO_WARNINGS

#include <windows.h>
#include <tlhelp32.h>
#include <winsvc.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Keep this in sync with the Node addon. */
typedef struct {
    UINT64 start;
    UINT64 end;
    UINT32 minLen;
    BOOL ascii;
    BOOL utf16;
    BOOL caseSensitive;
    const char *contains;
    SIZE_T maxResults;
} ScanStringOptions;

typedef void (*ScanCallback)(UINT64 addr, const char *text, const char *encoding);

#ifdef __cplusplus
extern "C" {
#endif

static void enableDebugPrivilege(void)
{
    static BOOL attempted = FALSE;
    if (attempted)
        return;

    attempted = TRUE;

    HANDLE token = NULL;
    if (!OpenProcessToken(GetCurrentProcess(),
                          TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
                          &token)) {
        return;
    }

    LUID luid;
    if (LookupPrivilegeValueA(NULL, "SeDebugPrivilege", &luid)) {
        TOKEN_PRIVILEGES privileges = {0};
        privileges.PrivilegeCount = 1;
        privileges.Privileges[0].Luid = luid;
        privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

        AdjustTokenPrivileges(token, FALSE, &privileges,
                              sizeof(privileges), NULL, NULL);
    }

    CloseHandle(token);
}

__declspec(dllexport)
HANDLE OpenProcessForNode(DWORD pid)
{
    enableDebugPrivilege();

    return OpenProcess(
        PROCESS_QUERY_INFORMATION |
        PROCESS_QUERY_LIMITED_INFORMATION |
        PROCESS_VM_READ |
        PROCESS_VM_OPERATION,
        FALSE,
        pid
    );
}

__declspec(dllexport)
BOOL CloseHandleForNode(HANDLE handle)
{
    return handle ? CloseHandle(handle) : FALSE;
}

__declspec(dllexport)
BOOL ReadMemoryForNode(HANDLE process,
                       LPCVOID address,
                       LPVOID buffer,
                       SIZE_T size,
                       SIZE_T *bytesRead)
{
    if (!process || !address || !buffer || !bytesRead)
        return FALSE;

    return ReadProcessMemory(process, address, buffer, size, bytesRead);
}

__declspec(dllexport)
DWORD FindPidsByExeNameA(const char *exeName,
                         DWORD *outPids,
                         DWORD maxCount,
                         BOOL caseInsensitive)
{
    if (!exeName || !outPids || maxCount == 0)
        return 0;

    enableDebugPrivilege();

    wchar_t target[260] = {0};
    if (!MultiByteToWideChar(CP_UTF8, 0, exeName, -1, target, 260))
        return 0;

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE)
        return 0;

    PROCESSENTRY32W entry = {0};
    entry.dwSize = sizeof(entry);

    DWORD count = 0;

    if (Process32FirstW(snapshot, &entry)) {
        do {
            int cmp = caseInsensitive
                ? _wcsicmp(entry.szExeFile, target)
                : wcscmp(entry.szExeFile, target);

            if (cmp == 0) {
                if (count < maxCount)
                    outPids[count] = entry.th32ProcessID;
                ++count;
            }
        } while (Process32NextW(snapshot, &entry));
    }

    CloseHandle(snapshot);
    return count;
}

__declspec(dllexport)
DWORD FindServicePidA(const char *serviceName)
{
    if (!serviceName)
        return 0;

    enableDebugPrivilege();

    wchar_t serviceNameW[256] = {0};
    if (!MultiByteToWideChar(CP_UTF8, 0, serviceName, -1,
                             serviceNameW, 256)) {
        return 0;
    }

    SC_HANDLE scm = OpenSCManagerW(NULL, NULL, SC_MANAGER_CONNECT);
    if (!scm)
        return 0;

    SC_HANDLE service = OpenServiceW(scm, serviceNameW, SERVICE_QUERY_STATUS);
    if (!service) {
        CloseServiceHandle(scm);
        return 0;
    }

    SERVICE_STATUS_PROCESS status = {0};
    DWORD needed = 0;
    DWORD pid = 0;

    if (QueryServiceStatusEx(service,
                             SC_STATUS_PROCESS_INFO,
                             (LPBYTE)&status,
                             sizeof(status),
                             &needed)) {
        pid = status.dwProcessId;
    }

    CloseServiceHandle(service);
    CloseServiceHandle(scm);
    return pid;
}

static BOOL containsText(const char *text,
                         const char *needle,
                         BOOL caseSensitive)
{
    if (!needle || !*needle)
        return TRUE;
    if (!text)
        return FALSE;

    if (caseSensitive)
        return strstr(text, needle) != NULL;

    size_t textLen = strlen(text);
    size_t needleLen = strlen(needle);

    if (needleLen > textLen)
        return FALSE;

    for (size_t i = 0; i + needleLen <= textLen; ++i) {
        size_t j = 0;

        for (; j < needleLen; ++j) {
            char a = text[i + j];
            char b = needle[j];

            if (a >= 'A' && a <= 'Z')
                a = (char)(a + ('a' - 'A'));
            if (b >= 'A' && b <= 'Z')
                b = (char)(b + ('a' - 'A'));

            if (a != b)
                break;
        }

        if (j == needleLen)
            return TRUE;
    }

    return FALSE;
}

__declspec(dllexport)
DWORD ScanStringsForNode(HANDLE process,
                         ScanStringOptions *options,
                         ScanCallback callback)
{
    if (!process || !options || !callback)
        return 0;

    enableDebugPrivilege();

    UINT64 address = options->start;
    UINT64 scanEnd = options->end ? options->end : 0x7fffffffffffULL;
    DWORD resultCount = 0;

    while (address < scanEnd && resultCount < options->maxResults) {
        MEMORY_BASIC_INFORMATION mbi = {0};

        if (!VirtualQueryEx(process,
                            (LPCVOID)(UINT_PTR)address,
                            &mbi,
                            sizeof(mbi))) {
            break;
        }

        UINT64 regionBase = (UINT64)(UINT_PTR)mbi.BaseAddress;
        UINT64 regionSize = (UINT64)mbi.RegionSize;
        address = regionBase + regionSize;

        if (regionSize == 0 || mbi.State != MEM_COMMIT)
            continue;
        if (mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD))
            continue;

        /* Avoid trying to allocate an entire unusually large region at once. */
        const UINT64 maxRegionRead = 16ULL * 1024ULL * 1024ULL;
        SIZE_T bytesToRead = (SIZE_T)(regionSize > maxRegionRead
            ? maxRegionRead
            : regionSize);

        char *buffer = (char *)malloc(bytesToRead);
        if (!buffer)
            continue;

        SIZE_T bytesRead = 0;
        BOOL readOk = ReadProcessMemory(process,
                                        (LPCVOID)(UINT_PTR)regionBase,
                                        buffer,
                                        bytesToRead,
                                        &bytesRead);

        if (!readOk || bytesRead == 0) {
            free(buffer);
            continue;
        }

        SIZE_T pos = 0;

        while (pos < bytesRead && resultCount < options->maxResults) {
            if (!options->ascii) {
                ++pos;
                continue;
            }

            SIZE_T end = pos;
            while (end < bytesRead &&
                   buffer[end] >= 0x20 &&
                   buffer[end] <= 0x7e) {
                ++end;
            }

            SIZE_T length = end - pos;
            if (length >= options->minLen) {
                char text[512];
                SIZE_T copyLen = length < sizeof(text) - 1
                    ? length
                    : sizeof(text) - 1;

                memcpy(text, buffer + pos, copyLen);
                text[copyLen] = '\0';

                if (containsText(text,
                                 options->contains,
                                 options->caseSensitive)) {
                    callback(regionBase + pos, text, "ascii");
                    ++resultCount;
                }
            }

            pos = (end < bytesRead) ? end + 1 : end;
        }

        free(buffer);
    }

    /* UTF-16 is kept in the public options for compatibility, but is not
       scanned by this implementation yet. */
    return resultCount;
}

#ifdef __cplusplus
}
#endif
