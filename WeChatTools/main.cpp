#include "main.h"


int _tmain(int nargv, WCHAR* argvs[])
{
    /*
    DWORD dwId = 0;
    HWND hCalc = FindWindow(NULL, L"微信");
    DWORD dwPid = 0;
    DWORD dwRub = GetWindowThreadProcessId(hCalc, &dwPid);
    if (!dwPid) {
        wstring info = L"请先启动目标进程！";
        MessageBox(NULL, info.c_str(), _T("警告"), MB_ICONWARNING);
        return 1;
    }
    wchar_t* wStr = NULL;
    
    if (nargv == 1) {
        return 1;
    }
    else if (nargv == 2) {
        wStr = argvs[1];
        Inject(dwPid, argvs[1]);
    }
    else if (nargv == 3 && !((wstring)argvs[1]).compare(L"-r")) {
        wStr = argvs[2];
        RemoveDll(dwPid);
    }
    return 0;
    */

    const std::string conf = ReadConf(confname);
    if (conf.empty()) {
        wstring info = L"配置文件conf.json不存在！";
        MessageBox(NULL, info.c_str(), _T("警告"), MB_ICONWARNING);
        return 1;
    }

    std::wstring szAppName = GetWeChatInstallDir();
    if (szAppName.length() == 0)
        return 1;
    szAppName += TEXT("\\WeChat.exe");

    STARTUPINFO si;
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(STARTUPINFO));
    ZeroMemory(&pi, sizeof(PROCESS_INFORMATION));
    si.cb = sizeof(STARTUPINFO);

    if (CreateProcess((LPCTSTR)szAppName.c_str(), NULL, NULL, NULL, FALSE, NORMAL_PRIORITY_CLASS, NULL, NULL, &si, &pi))
    {
        WaitForInputIdle(pi.hProcess, INFINITE);

        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);

        DWORD dwPid = pi.dwProcessId;

        closeMutant(dwPid);

        Inject(dwPid, (wchar_t*)dllname);

        while (!IsWxLogin(dwPid)) {
            Sleep(100);
        }

        StartOctopus(dwPid, conf.c_str());

        return 0;
    }

    return 1;
}