#include "base.h"

#include <fstream>
#include <vector>

#pragma comment(lib,"ntdll")

DWORD GetWeChatRobotBase() {
    if (!hProcess)
        return 0;
    DWORD dwWriteSize = 0;
    LPVOID pRemoteAddress = VirtualAllocEx(hProcess, NULL, 1, MEM_COMMIT, PAGE_READWRITE);
    if (pRemoteAddress)
        WriteProcessMemory(hProcess, pRemoteAddress, dllname, wcslen(dllname) * 2 + 2, &dwWriteSize);
    else
        return 0;
    DWORD dwHandle, dwID;
    LPVOID pFunc = GetModuleHandleW;
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)pFunc, pRemoteAddress, 0, &dwID);
    if (hThread) {
        WaitForSingleObject(hThread, INFINITE);
        GetExitCodeThread(hThread, &dwHandle);
    }
    else {
        return 0;
    }
    CloseHandle(hThread);
    VirtualFreeEx(hProcess, pRemoteAddress, 0, MEM_RELEASE);
    return dwHandle;
}

#define NT_SUCCESS(status) (status>=0)

#define STATUS_INFO_LENGTH_MISMATCH  ((NTSTATUS)0xC0000004L)

enum PROCESSINFOCLASS {
    ProcessHandleInformation = 51
};

typedef struct _PROCESS_HANDLE_TABLE_ENTRY_INFO {
    HANDLE HandleValue;
    ULONG_PTR HandleCount;
    ULONG_PTR PointerCount;
    ULONG GrantedAccess;
    ULONG ObjectTypeIndex;
    ULONG HandleAttributes;
    ULONG Reserved;
}PROCESS_HANDLE_TABLE_ENTRY_INFO, * PROCESS_HANDLE_TABLE_ENTRY;


// private
typedef struct _PROCESS_HANDLE_SNAPSHOT_INFORMATION {
    ULONG_PTR NumberOfHandles;
    ULONG_PTR Reserved;
    PROCESS_HANDLE_TABLE_ENTRY_INFO Handles[1];
}PROCESS_HANDLE_SNAPSHOT_INFORMATION, * PROCESS_HANDLE_SNAPSHOT;


extern "C" NTSTATUS NTAPI NtQueryInformationProcess(
    _In_ HANDLE ProcessHandle,
    _In_ PROCESSINFOCLASS ProcessInformationClass,
    _In_ _Out_writes_bytes_(ProcessInformationLength) PVOID ProcessInformation,
    _In_ ULONG ProcessInformationLength,
    _Out_opt_ PULONG ReturnLength);

typedef enum _OBJECT_INFORMATION_CLASS {
    ObjectNameInformation = 1
} OBJECT_INFORMATION_CLASS;

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING;

typedef struct _OBJECT_NAME_INFORMATION {
    UNICODE_STRING Name;
} OBJECT_NAME_INFORMATION, * POBJECT_NAME_INFORMATION;

extern "C" NTSTATUS NTAPI NtQueryObject(
    _In_opt_ HANDLE Handle,
    _In_ OBJECT_INFORMATION_CLASS ObjectInformationClass,
    _Out_writes_bytes_opt_(ObjectInformationLength) PVOID ObjectInformation,
    _In_ ULONG ObjectInformationLength,
    _Out_opt_ PULONG ReturnLength);

BOOL closeMutant(DWORD pid) {
    HANDLE hProcess = ::OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_DUP_HANDLE, FALSE, pid);
    if (!hProcess) {
        printf("Failed to open WeChat process handle (error=%u)\n", GetLastError());
        return FALSE;
    }

    ULONG size = 1 << 10;
    std::unique_ptr<BYTE[]> buffer;
    for (;;) {
        buffer = std::make_unique<BYTE[]>(size);
        auto status = ::NtQueryInformationProcess(hProcess, ProcessHandleInformation,
            buffer.get(), size, &size);
        if (NT_SUCCESS(status)) {
            break;
        }
        if (status == STATUS_INFO_LENGTH_MISMATCH) {
            size += 1 << 10;
            continue;
        }
        printf("Error enumerating handles\n");
        return FALSE;
    }

    WCHAR targetName[256];
    DWORD sessionId;
    ::ProcessIdToSessionId(pid, &sessionId);
    ::swprintf_s(targetName,
        L"\\Sessions\\%u\\BaseNamedObjects\\_WeChat_App_Instance_Identity_Mutex_Name",
        sessionId);
    auto len = ::wcslen(targetName);

    auto info = reinterpret_cast<PROCESS_HANDLE_SNAPSHOT_INFORMATION*>(buffer.get());
    for (ULONG i = 0; i < info->NumberOfHandles; i++) {
        HANDLE h = info->Handles[i].HandleValue;
        HANDLE hTarget;
        if (!::DuplicateHandle(hProcess, h, ::GetCurrentProcess(), &hTarget,
            0, FALSE, DUPLICATE_SAME_ACCESS)) {
            continue;        // move to next handle
        }
        BYTE nameBuffer[1 << 10];
        auto status = ::NtQueryObject(hTarget, ObjectNameInformation,
            nameBuffer, sizeof(nameBuffer), nullptr);
        auto name = reinterpret_cast<UNICODE_STRING*>(nameBuffer);
        if (name->Buffer && ::_wcsnicmp(name->Buffer, targetName, len) == 0) {
            // found it!
            ::DuplicateHandle(hProcess, h, ::GetCurrentProcess(), &h,
                0, false, DUPLICATE_CLOSE_SOURCE);
            printf("Found mutant and closed it!\n");
        }
    }

    return TRUE;
}

PVOID pRemoteGetProc = NULL;

struct GetProcAddrStruct {
    DWORD hModuleNameAddr;
    DWORD funcnameAddr;
};

DWORD GetWeChatPid() {
    HWND hCalc = FindWindow(NULL, L"Œ¢–≈");
    DWORD wxPid = 0;
    GetWindowThreadProcessId(hCalc, &wxPid);
    if (wxPid == 0) {
        hCalc = FindWindow(NULL, L"Œ¢–≈≤‚ ‘∞Ê");
        GetWindowThreadProcessId(hCalc, &wxPid);
    }
    return wxPid;
}

static PVOID CreateGetProcFuncInWeChatProcess() {
#ifdef _WIN64
    DWORD pGetModuleHandleW = (DWORD)GetSystem32ProcAddr(L"\\KnownDlls32\\kernel32.dll", "GetModuleHandleW");
    DWORD pGetProcAddress = (DWORD)GetSystem32ProcAddr(L"\\KnownDlls32\\kernel32.dll", "GetProcAddress");
#else
    DWORD pGetModuleHandleW = (DWORD)GetModuleHandleW;
    DWORD pGetProcAddress = (DWORD)GetProcAddress;
#endif
    unsigned char asmcode[] = {
        0x55,                                   // push ebp;
        0x8B,0xEC,                              // mov ebp, esp;
        0x83,0xEC,0x40,                         // sub esp, 0x40;
        0x57,                                   // push edi;
        0x51,                                   // push ecx;
        0x8B,0x7D,0x08,                         // mov edi, dword ptr[ebp + 0x8];
        0x8B,0x07,                              // mov eax,dword ptr[edi];
        0x50,                                   // push eax;
        0xE8,0x00,0x00,0x00,0x00,               // call GetModuleHandleW;
        0x83,0xC4,0x04,                         // add esp,0x4;
        0x83,0xC7,0x04,                         // add edi,0x4;
        0x8B,0x0F,                              // mov ecx, dword ptr[edi];
        0x51,                                   // push ecx;
        0x50,                                   // push eax;
        0xE8,0x00,0x00,0x00,0x00,               // call GetProcAddress;
        0x83,0xC4,0x08,                         // add esp, 0x8;
        0x59,                                   // pop ecx;
        0x5F,                                   // pop edi;
        0x8B,0xE5,                              // mov esp, ebp;
        0x5D,                                   // pop ebp;
        0xC3                                    // retn;
    };
    PVOID call1 = (PVOID)&asmcode[15];
    PVOID call2 = (PVOID)&asmcode[30];
    DWORD wxpid = GetWeChatPid();
    SIZE_T dwWriteSize;
    LPVOID pRemoteAddress = VirtualAllocEx(hProcess, NULL, 1, MEM_COMMIT, PAGE_EXECUTE);
    if (!pRemoteAddress)
        return 0;
    *(DWORD*)call1 = pGetModuleHandleW - (DWORD)pRemoteAddress - 14 - 5;
    *(DWORD*)call2 = pGetProcAddress - (DWORD)pRemoteAddress - 29 - 5;
    WriteProcessMemory(hProcess, pRemoteAddress, asmcode, 43, &dwWriteSize);
    return pRemoteAddress;
}

DWORD GetRemoteProcAddr(const wchar_t* hModuleName, const char* funcname) {
    if (!hProcess || !pRemoteGetProc)
        return 0;
    LPVOID hModuleNameAddr = VirtualAllocEx(hProcess, NULL, 1, MEM_COMMIT, PAGE_READWRITE);
    LPVOID funcnameAddr = VirtualAllocEx(hProcess, NULL, 1, MEM_COMMIT, PAGE_READWRITE);
    GetProcAddrStruct* paramAndFunc = (GetProcAddrStruct*)::VirtualAllocEx(hProcess, 0, sizeof(GetProcAddrStruct), MEM_COMMIT, PAGE_READWRITE);
    if (!hModuleNameAddr || !funcnameAddr || !paramAndFunc) {
        return 0;
    }
    SIZE_T dwWriteSize;
    DWORD dwId;
    DWORD dwProcAddr = 0;
    if (hModuleNameAddr)
        WriteProcessMemory(hProcess, hModuleNameAddr, hModuleName, wcslen(hModuleName) * 2 + 2, &dwWriteSize);
    if (funcnameAddr)
        WriteProcessMemory(hProcess, funcnameAddr, funcname, strlen(funcname) + 1, &dwWriteSize);
    GetProcAddrStruct params = { 0 };
    params.hModuleNameAddr = (DWORD)hModuleNameAddr;
    params.funcnameAddr = (DWORD)funcnameAddr;
    if (paramAndFunc)
        WriteProcessMemory(hProcess, paramAndFunc, &params, sizeof(params), &dwWriteSize);
    HANDLE hThread = ::CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)pRemoteGetProc, (LPVOID)paramAndFunc, 0, &dwId);
    if (hThread) {
        WaitForSingleObject(hThread, INFINITE);
        GetExitCodeThread(hThread, &dwProcAddr);
        CloseHandle(hThread);
    }
    VirtualFreeEx(hProcess, hModuleNameAddr, 0, MEM_RELEASE);
    VirtualFreeEx(hProcess, funcnameAddr, 0, MEM_RELEASE);
    VirtualFreeEx(hProcess, paramAndFunc, 0, MEM_RELEASE);
    return dwProcAddr;
}

static BOOL GetWeChatInstallInfo(TCHAR* lpValueName, VOID* Value, DWORD lpcbData) {
    HKEY hKey = NULL;
    ZeroMemory(Value, lpcbData);
    LSTATUS lRet = RegOpenKeyEx(HKEY_CURRENT_USER, _T("SOFTWARE\\Tencent\\WeChat"), 0, KEY_QUERY_VALUE, &hKey);
    if (lRet != 0) {
        return false;
    }
    lRet = RegQueryValueEx(hKey, lpValueName, NULL, NULL, (LPBYTE)Value, &lpcbData);
    RegCloseKey(hKey);
    if (lRet != 0) {
        return false;
    }
    return true;
}

const std::wstring GetWeChatInstallDir() {
    TCHAR* szProductType = new TCHAR[MAX_PATH];
    GetWeChatInstallInfo((TCHAR*)TEXT("InstallPath"), (void*)szProductType, MAX_PATH);
    std::wstring wxdir(szProductType);
    delete[] szProductType;
    szProductType = NULL;
    return wxdir.length() == 0 ? TEXT("") : wxdir;
}

const std::string ReadConf(const std::string& path) {
    struct stat buffer;

    if (stat(path.c_str(), &buffer) != 0) {
        return "";
    }
    else {
        std::ifstream in(path, ios_base::binary);

        std::vector<char> buffer;
        buffer.assign(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());

        in.close();

        return std::string(buffer.begin(), buffer.end());
    }
}

BOOL IsWxLogin(DWORD dwPid) {
    hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPid);

    DWORD dwRet = 0;

    pRemoteGetProc = CreateGetProcFuncInWeChatProcess();
    DWORD pIsWxLogin = GetRemoteProcAddr(dllname, "isWxLogin");
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)pIsWxLogin, NULL, 0, &dwPid);
    if (hThread) {
        WaitForSingleObject(hThread, INFINITE);
        GetExitCodeThread(hThread, &dwRet);
        CloseHandle(hThread);
    }

    return dwRet == 1;
}

void StartOctopus(DWORD dwPid, const char* addr) {
    hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPid);

    LPVOID param = VirtualAllocEx(hProcess, NULL, strlen(addr) + 1, MEM_COMMIT, PAGE_READWRITE);
    WriteProcessMemory(hProcess, param, addr, strlen(addr) + 1, NULL);

    pRemoteGetProc = CreateGetProcFuncInWeChatProcess();
    DWORD pStartPorter = GetRemoteProcAddr(dllname, "StartOctopus");
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)pStartPorter, param, 0, 0);
    if (hThread) {
        WaitForSingleObject(hThread, INFINITE);
        CloseHandle(hThread);
    }
}

void StopOctopus(DWORD dwPid) {
    hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPid);

    pRemoteGetProc = CreateGetProcFuncInWeChatProcess();
    DWORD pStopPorter = GetRemoteProcAddr(dllname, "StopOctopus");
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)pStopPorter, NULL, 0, 0);
    if (hThread) {
        WaitForSingleObject(hThread, INFINITE);
        CloseHandle(hThread);
    }
    VirtualFreeEx(hProcess, pRemoteGetProc, 0, MEM_RELEASE);
}