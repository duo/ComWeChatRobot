#pragma once
#include <iostream>
#include "stdlib.h"
#include <tchar.h>
#include <Windows.h>
#include <stdio.h>
#include <windows.h>
#include <TlHelp32.h>
#include <atlconv.h>
#include <tchar.h>
#include <sys/stat.h>
#include <direct.h>

using namespace std;

void Inject(DWORD dwPid, wchar_t* wStr);
bool isFileExists_stat(string& name);
string wstring2string(wstring wstr);
BOOL RemoveDll(DWORD dwId);
extern HANDLE hProcess;
DWORD GetWeChatRobotBase();

#define dllname L"DWeChatRobot.dll"
#define SendImageOffset 0x000110BE

#define confname "conf.json"

const std::wstring GetWeChatInstallDir();
const std::string ReadConf(const std::string&);
BOOL closeMutant(DWORD pid);
BOOL IsWxLogin(DWORD dwPid);
void StartOctopus(DWORD dwPid, const char* addr);
void StopOctopus(DWORD dwPid);