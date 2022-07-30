#include "pch.h"
#include "Misc.h"

#include "shtypes.h"
#include "shlobj_core.h"

#include <codecvt>
#include <fstream>
#include <winhttp.h>

#pragma comment (lib, "rpcrt4.lib")
#pragma comment (lib, "winhttp.lib")

#define UA L"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.88 Safari/537.36 Edg/87.0.664.66"

// 通讯录左树偏移
#define LeftTreeOffset 0x23668F4

// 获取好友信息CALL1偏移
#define GetUserInfoCall1Offset 0x100BD5C0 - 0x10000000
// 获取好友信息CALL2偏移
#define GetUserInfoCall2Offset 0x10771980 - 0x10000000
// 获取好友信息CALL3偏移
#define GetUserInfoCall3Offset 0x104662A0 - 0x10000000
// 清理好友信息缓存参数
#define DeleteUserInfoCacheCall1Offset 0x106C52B0 - 0x10000000
// 清理好友信息缓存CALL2
#define DeleteUserInfoCacheCall2Offset 0x100BE6D0 - 0x10000000

WxUser GetSelf() {
	DWORD WeChatWinBase = GetWeChatWinBase();
	DWORD wxIdAddr = WeChatWinBase + 0x236607C;
	DWORD wxNickNameAddr = WeChatWinBase + 0x23660F4;

	WxUser user;

	{
		char* temp = NULL;
		char wxidbuffer[0x100] = { 0 };
		sprintf_s(wxidbuffer, "%s", (char*)wxIdAddr);
		if (strlen(wxidbuffer) < 0x6 || strlen(wxidbuffer) > 0x14)
		{
			//新的微信号 微信ID用地址保存
			temp = (char*)(*(DWORD*)wxIdAddr);
		}
		else
		{
			temp = (char*)wxIdAddr;
		}
		user.id = std::string(temp);
	}
	{
		char* temp = NULL;
		if (*(DWORD*)(wxNickNameAddr + 0x14) == 0xF) {
			temp = (*((DWORD*)wxNickNameAddr) != 0) ? (char*)wxNickNameAddr : (char*)"null";
		}
		else {
			temp = (*((DWORD*)wxNickNameAddr) != 0) ? (char*)(*(DWORD*)wxNickNameAddr) : (char*)"null";
		}
		user.nickName = std::string(temp);
	}

	if (user.nickName.empty()) {
		user.nickName = user.id;
	}
	user.remark = user.nickName;

	return user;
}

WxUser GetUserInfo(wchar_t* wxId) {
	DWORD WeChatWinBase = GetWeChatWinBase();
	DWORD WxGetUserInfoCall1 = WeChatWinBase + GetUserInfoCall1Offset;
	DWORD WxGetUserInfoCall2 = WeChatWinBase + GetUserInfoCall2Offset;
	DWORD WxGetUserInfoCall3 = WeChatWinBase + GetUserInfoCall3Offset;
	DWORD DeleteUserInfoCacheCall1 = WeChatWinBase + DeleteUserInfoCacheCall1Offset;
	DWORD DeleteUserInfoCacheCall2 = WeChatWinBase + DeleteUserInfoCacheCall2Offset;
	char buffer[0x3FC] = { 0 };
	WxBaseStruct pWxid(wxId);
	DWORD address = 0;
	DWORD isSuccess = 0;
	__asm
	{
		pushad;
		call WxGetUserInfoCall1;
		lea ebx, buffer;
		push ebx;
		sub esp, 0x14;
		mov esi, eax;
		lea eax, pWxid;
		mov ecx, esp;
		push eax;
		call WxGetUserInfoCall2;
		mov ecx, esi;
		call WxGetUserInfoCall3;
		mov isSuccess, eax;
		mov address, ebx;
		popad;
	}

	WxUser user;
	user.id = as_utf8(wxId);
	user.nickName = user.id;

	if (isSuccess) {
		DWORD wxNickNameAddr = address + 0x6C;
		DWORD wxRemarkAddr = address + 0x58;

		wchar_t* wstemp = NULL;
		wstemp = ((*((DWORD*)wxNickNameAddr)) != 0) ? (WCHAR*)(*((LPVOID*)wxNickNameAddr)) : NULL;
		if (wstemp != NULL) {
			//user.nickName = std::wstring(wstemp);
			user.nickName = as_utf8(wstemp);
		}
		wstemp = ((*((DWORD*)wxRemarkAddr)) != 0) ? (WCHAR*)(*((LPVOID*)wxRemarkAddr)) : NULL;
		if (wstemp != NULL) {
			//user.remark = std::wstring(wstemp);
			user.remark = as_utf8(wstemp);
		}
	}

	if (user.remark.empty()) {
		user.remark = user.nickName;
	}

	char deletebuffer[0x410] = { 0 };
	__asm {
		pushad;
		lea ecx, deletebuffer;
		call DeleteUserInfoCacheCall1;
		push eax;
		lea ebx, buffer;
		mov ecx, ebx;
		call DeleteUserInfoCacheCall2;
		popad;
	}

	return user;
}

std::vector<WxUser> GetFriends() {
	std::vector<WxUser> friends;

	DWORD WeChatWinBase = GetWeChatWinBase();
	DWORD LeftTreeAddr = 0;
	DWORD RightTreeAddr = 0;
	DWORD LeftTreeHead = 0;
	DWORD baseAddr = WeChatWinBase + LeftTreeOffset;
	__asm {
		pushad;
		mov eax, dword ptr[baseAddr];
		mov eax, dword ptr[eax];
		mov eax, dword ptr[eax + 0x4C];
		mov ecx, dword ptr[eax];
		mov LeftTreeAddr, ecx;
		mov LeftTreeHead, eax;
		mov ecx, dword ptr[eax + 0x4];
		mov RightTreeAddr, ecx;
		popad;
	}

	while (1) {
		DWORD wxIdAddr = 0;
		DWORD wxNumberAddr = 0;
		DWORD wxNickNameAddr = 0;
		DWORD wxRemarkAddr = 0;

		__asm {
			pushad;
			mov eax, dword ptr[LeftTreeAddr];
			mov ecx, eax;
			add ecx, 0x30;
			mov wxIdAddr, ecx;
			mov ecx, eax;
			add ecx, 0x44;
			mov wxNumberAddr, ecx;
			mov ecx, eax;
			add ecx, 0x8C;
			mov wxNickNameAddr, ecx;
			mov ecx, eax;
			add ecx, 0x78;
			mov wxRemarkAddr, ecx;
			mov ecx, dword ptr[eax];
			mov LeftTreeAddr, ecx;
			popad;
		}

		WxUser user;

		if (wxIdAddr != NULL) {
			DWORD length = *(DWORD*)(wxIdAddr + 0x4);
			DWORD bufferaddr = *(DWORD*)(wxIdAddr);
			if (length) {
				user.id = as_utf8((wchar_t*)bufferaddr);
			}
		}
		if (wxNickNameAddr != NULL) {
			DWORD length = *(DWORD*)(wxNickNameAddr + 0x4);
			DWORD bufferaddr = *(DWORD*)(wxNickNameAddr);
			if (length) {
				user.nickName = as_utf8((wchar_t*)bufferaddr);
			}
		}
		if (wxRemarkAddr != NULL) {
			DWORD length = *(DWORD*)(wxRemarkAddr + 0x4);
			DWORD bufferaddr = *(DWORD*)(wxRemarkAddr);
			if (length) {
				user.remark = as_utf8((wchar_t*)bufferaddr);
			}
		}

		if (user.nickName.empty()) {
			user.nickName = user.id;
		}
		if (user.remark.empty()) {
			user.remark = user.nickName;
		}
		if (!user.id.empty()) {
			friends.push_back(user);
		}

		if (LeftTreeAddr == LeftTreeHead) {
			break;
		}
	}

	return friends;
}

BOOL GetWeChatInstallInfo(TCHAR* lpValueName, VOID* Value, DWORD lpcbData) {
	HKEY hKey = NULL;
	ZeroMemory(Value, lpcbData);
	LSTATUS lRet = RegOpenKeyEx(HKEY_CURRENT_USER, L"SOFTWARE\\Tencent\\WeChat", 0, KEY_QUERY_VALUE, &hKey);
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

std::wstring GetWeChatFileSaveDir() {
	TCHAR* szProductType = new TCHAR[MAX_PATH];
	GetWeChatInstallInfo((TCHAR*)TEXT("FileSavePath"), (void*)szProductType, MAX_PATH);
	std::wstring wxdir(szProductType);
	delete[] szProductType;
	szProductType = NULL;
	return wxdir.length() == 0 ? TEXT("") : wxdir;
}

std::wstring GetMyDocument() {
	LPITEMIDLIST ppidl;
	WCHAR defaultDir[260];
	WCHAR docDir[262];

	memset(defaultDir, 0, sizeof(defaultDir));
	memset(docDir, 0, 0x208);
	ppidl = 0;

	SHGetSpecialFolderLocation(0, CSIDL_PERSONAL, &ppidl);
	if (ppidl && SHGetPathFromIDListW(ppidl, docDir)) {
		GetShortPathNameW(defaultDir, docDir, 0x104);
	}

	return std::wstring(docDir);
}

std::wstring GetFileSavePath() {
	std::wstring path = GetWeChatFileSaveDir();
	if (path == L"" || path == L"MyDocument:") {
		path = GetMyDocument();
	}

	return path + L"\\WeChat Files\\";
}

const std::string gen_uuid() {
	UUID uuid;
	RPC_CSTR  uuid_str;
	std::string uuid_out;

	UuidCreate(&uuid);
	UuidToStringA(&uuid, &uuid_str);
	uuid_out = (char*)uuid_str;
	RpcStringFreeA(&uuid_str);
	return uuid_out;
}

bool ends_with(const std::string& mainStr, const std::string& toMatch) {
	if (mainStr.size() >= toMatch.size() &&
		mainStr.compare(mainStr.size() - toMatch.size(), toMatch.size(), toMatch) == 0) {
		return true;
	} else {
		return false;
	}
}

const std::string read_file(const std::string& path) {
	struct stat buffer;

	if (stat(path.c_str(), &buffer) != 0) {
		return "";
	} else {
		std::ifstream in(path, ios_base::binary);

		std::vector<char> buffer;
		buffer.assign(std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>());

		in.close();

		return std::string(buffer.begin(), buffer.end());
	}
}

BOOL write_file(const std::string& filepath, const std::string& content) {
	std::ofstream out(filepath, ios_base::binary);
	if (!out) {
		return false;
	}

	out.write(content.c_str(), content.size());
	out.close();

	return out.good();
}

size_t write_data(void* contents, size_t size, size_t nmemb, void* userp) {
	((std::string*)userp)->append((char*)contents, size * nmemb);
	return size * nmemb;
}

const std::string download_file(const std::string& url) {
	const char* raw_url = url.c_str();

	const char* url_start = raw_url;
	while (*url_start == ' ') {
		url_start++;
	}
	bool is_https = strstr(url_start, "https:") || strstr(url_start, "HTTPS:");

	const char* base_start = strstr(raw_url, "://");
	if (base_start == NULL) {
		for (base_start = raw_url; *base_start == ' '; base_start++); // skipping leading spaces		
	} else {
		base_start += 3; // 3 ---> strlen("://")
	}

	const char* base_end = strstr(base_start, "/");
	if (base_end == NULL) {
		base_end = base_start + strlen(base_start);
	}

	size_t out_size;

	size_t base_size = base_end - base_start;
	wchar_t* w_base = new wchar_t[base_size + 1];
	mbstowcs_s(&out_size, w_base, base_size + 1, base_start, base_size);

	size_t end_size = strlen(base_end);
	wchar_t* w_route = new wchar_t[end_size + 1];
	mbstowcs_s(&out_size, w_route, end_size + 1, base_end, end_size);

	std::string response;

	HINTERNET hSession = NULL, hConnect = NULL, hRequest = NULL;
	BOOL bResults = FALSE;
	DWORD dwSize = 0;
	DWORD dwDownloaded = 0;
	LPSTR pszOutBuffer;

	hSession = WinHttpOpen(UA, WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);

	if (hSession) {
		hConnect = WinHttpConnect(hSession, w_base, is_https ? INTERNET_DEFAULT_HTTPS_PORT : INTERNET_DEFAULT_HTTP_PORT, 0);
	}
	if (hConnect) {
		hRequest = WinHttpOpenRequest(hConnect, L"GET", w_route, NULL, WINHTTP_NO_REFERER, WINHTTP_DEFAULT_ACCEPT_TYPES, is_https ? WINHTTP_FLAG_SECURE : 0);
	}
	if (hRequest) {
		if (is_https) {
			DWORD dwFlags =
				SECURITY_FLAG_IGNORE_UNKNOWN_CA |
				SECURITY_FLAG_IGNORE_CERT_WRONG_USAGE |
				SECURITY_FLAG_IGNORE_CERT_CN_INVALID |
				SECURITY_FLAG_IGNORE_CERT_DATE_INVALID;
			WinHttpSetOption(
				hRequest,
				WINHTTP_OPTION_SECURITY_FLAGS,
				&dwFlags,
				sizeof(dwFlags));
		}

		bResults = WinHttpSendRequest(hRequest, WINHTTP_NO_ADDITIONAL_HEADERS, 0, WINHTTP_NO_REQUEST_DATA, 0, 0, 0);
	}

	if (bResults) {
		bResults = WinHttpReceiveResponse(hRequest, NULL);
	}

	if (bResults) {
		do
		{
			// Check for available data.
			dwSize = 0;
			if (!WinHttpQueryDataAvailable(hRequest, &dwSize)) {
				printf("Error %u in WinHttpQueryDataAvailable.\n", GetLastError());
			}

			// Allocate space for the buffer.
			pszOutBuffer = new char[dwSize + 1];
			if (!pszOutBuffer) {
				printf("Out of memory\n");
				dwSize = 0;
			} else {
				// Read the data.
				ZeroMemory(pszOutBuffer, dwSize + 1);

				if (!WinHttpReadData(hRequest, (LPVOID)pszOutBuffer, dwSize, &dwDownloaded)) {
					printf("Error %u in WinHttpReadData.\n", GetLastError());
				} else {
					response.append(pszOutBuffer, dwSize);
				}

				// Free the memory allocated to the buffer.
				delete[] pszOutBuffer;
			}
		} while (dwSize > 0);
	}

	// Report any errors.
	if (!bResults) {
		printf("Error %d has occurred.\n", GetLastError());
	}

	// Close any open handles.
	if (hRequest) { WinHttpCloseHandle(hRequest); }
	if (hConnect) { WinHttpCloseHandle(hConnect); }
	if (hSession) { WinHttpCloseHandle(hSession); }

	delete[] w_base;
	delete[] w_route;

	return response;
}

const std::string as_utf8(const wchar_t* src) {
	if (src == NULL) {
		return "";
	}
	int len = WideCharToMultiByte(CP_UTF8, 0, src, -1, NULL, 0, NULL, NULL);
	char* szUTF8 = new char[len + 1];
	memset(szUTF8, 0, len + 1);
	WideCharToMultiByte(CP_UTF8, 0, src, -1, szUTF8, len, NULL, NULL);
	std::string strTemp(szUTF8);
	delete[] szUTF8;
	return strTemp;
}

const std::string as_utf8(const std::wstring& src) {
	return as_utf8(src.c_str());
}

const std::wstring as_wide(const std::string& src) {
	std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> converter;
	return converter.from_bytes(src);
}