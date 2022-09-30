#include "pch.h"
#include <vector>
#include <winsock2.h>
#include <Ws2tcpip.h>
#include <map>
#include "json/json.hpp"
using namespace nlohmann;

#pragma comment(lib, "ws2_32.lib")

using namespace std;

#define CLTIP "127.0.0.1"

// ������Ϣ��HOOK��ַƫ��
#define ReceiveMessageHookOffset 0x655F0F4C - 0x650A0000 // 0x5D39C359 - 0x5D1F0000
// ������ϢHOOK��CALLƫ��
#define ReceiveMessageNextCallOffset 0x65B36350 - 0x650A0000 // 0x5D5F7F00 - 0x5D1F0000

// ������Ϣ��HOOK��ַƫ��
#define SendMessageHookOffset 0x78B88E42 - 0x786A0000
// ������ϢHOOK��CALLƫ��
#define SendMessageNextCallOffset 0x78AA8170 - 0x786A0000

// ������Ϣ��HOOK��ַƫ��
#define UpdateMessageHookOffset 0x5D6D8A4C - 0x5D1F0000
// ������ϢHOOK��CALLƫ��
#define UpdateMessageNextCallOffset 0x5D6D3430 - 0x5D1F0000

#define READ_WSTRING(addr, offset) ((*(DWORD *)(addr + offset + 0x4) == 0) ? wstring(L"") : wstring((wchar_t *)(*(DWORD *)(addr + offset)), *(DWORD *)(addr + offset + 0x4)))

static int SRVPORT = 0;

// �Ƿ���������ϢHOOK��־
BOOL ReceiveMessageHooked = false;
// ����HOOKǰ���ֽ��룬���ڻָ�
static char OldReceiveMessageAsmCode[5] = {0};
static char OldSendMessageAsmCode[5] = {0};
static char OldUpdateMessageAsmCode[5] = {0};
static DWORD WeChatWinBase = GetWeChatWinBase();
// ������ϢHOOK��ַ
static DWORD ReceiveMessageHookAddress = WeChatWinBase + ReceiveMessageHookOffset;
// ������ϢHOOK��CALL��ַ
static DWORD ReceiveMessageNextCall = WeChatWinBase + ReceiveMessageNextCallOffset;
// ����HOOK����ת��ַ
static DWORD ReceiveMessageJmpBackAddress = ReceiveMessageHookAddress + 0x5;
// ������ϢHOOK��ַ
static DWORD SendMessageHookAddress = WeChatWinBase + SendMessageHookOffset;
// ������ϢHOOK��CALL��ַ
static DWORD SendMessageNextCall = WeChatWinBase + SendMessageNextCallOffset;
// ����HOOK����ת��ַ
static DWORD SendMessageJmpBackAddress = SendMessageHookAddress + 0x5;
// ������ϢHOOK��ַ
static DWORD UpdateMessageHookAddress = WeChatWinBase + UpdateMessageHookOffset;
// ������ϢHOOK��CALL��ַ
static DWORD UpdateMessageNextCall = WeChatWinBase + UpdateMessageNextCallOffset;
// ����HOOK����ת��ַ
static DWORD UpdateMessageJmpBackAddress = UpdateMessageHookAddress + 0x5;

struct SocketMessageStruct
{
    char *buffer;
    int length;
    ~SocketMessageStruct()
    {
        if (this->buffer != NULL)
        {
            delete[] this->buffer;
            this->buffer = NULL;
        }
    }
};

// ͨ��socket����Ϣ���͸������
BOOL SendSocketMessage(const char *buffer, size_t len)
{
    if (SRVPORT == 0)
    {
        return false;
    }
    SOCKET clientsocket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (clientsocket < 0)
    {
#ifdef _DEBUG
        cout << "create socket error,"
             << " errno:" << errno << endl;
#endif
        return false;
    }
    BOOL status = false;
    sockaddr_in clientAddr;
    memset(&clientAddr, 0, sizeof(clientAddr));
    clientAddr.sin_family = AF_INET;
    clientAddr.sin_port = htons((u_short)SRVPORT);
    InetPtonA(AF_INET, CLTIP, &clientAddr.sin_addr.s_addr);

    if (connect(clientsocket, reinterpret_cast<sockaddr *>(&clientAddr), sizeof(sockaddr)) < 0)
    {
#ifdef _DEBUG
        cout << "connect error,"
             << " errno:" << errno << endl;
#endif
        return false;
    }
    char recvbuf[1024] = {0};
    int ret = send(clientsocket, buffer, len, 0);
    if (ret == -1 || ret == 0)
    {
#ifdef _DEBUG
        cout << "send fail,"
             << " errno:" << errno << endl;
#endif
        closesocket(clientsocket);
        return false;
    }
    memset(recvbuf, 0, sizeof(recvbuf));
    ret = recv(clientsocket, recvbuf, sizeof(recvbuf), 0);
    closesocket(clientsocket);
    if (ret == -1 || ret == 0)
    {
#ifdef _DEBUG
        cout << "the server close" << endl;
#endif
        return false;
    }
    return true;
}

void SendSocketMessageInThread(SocketMessageStruct *param)
{
    if (param == NULL)
        return;
    unique_ptr<SocketMessageStruct> sms(param);
    json jMsg = json::parse(param->buffer, param->buffer + param->length, nullptr, false);
    if (jMsg.is_discarded() == true)
    {
        return;
    }
    string jstr = jMsg.dump() + "\n";
    LOG(INFO) << "msgid: " << jMsg["msgid"].get<ULONG64>() << " send begin." << endl;
    LOG(INFO) << "type: " << jMsg["type"].get<int>() << ", sender: " << jMsg["wxid"].get<string>() << endl;
    LOG(INFO) << "content size: " << jstr.length() << endl;
#ifdef USE_COM
    // ͨ�����ӵ㣬����Ϣ�㲥���ͻ��ˣ����㲥���̷����߳�����ɣ��ͻ��˲ſ��Եȴ�ͼƬ���������
    VARIANT vsaValue;
    _variant_t szWMsg = (_variant_t)utf8_to_unicode(jstr.c_str()).c_str();
    vsaValue.vt = VT_ARRAY | VT_VARIANT;
    SAFEARRAYBOUND rgsaBound = {1, 0};
    SAFEARRAY *psaValue = SafeArrayCreate(VT_VARIANT, 1, &rgsaBound);
    long index = 0;
    // ���ݴ�С����16382���ַ����ͻ��˵��ÿ��ܳ����쳣����˽����ݷ��밲ȫ�����д���
    HRESULT hr = SafeArrayPutElement(psaValue, &index, &szWMsg);
    V_ARRAY(&vsaValue) = psaValue;
    DWORD type = jMsg["type"].get<DWORD>();
    ULONG64 msgid = (type != 10000) ? jMsg["msgid"].get<ULONG64>() : 0;
    PostComMessage(jMsg["pid"].get<int>(), WX_MESSAGE, msgid, &vsaValue);
#endif
    SendSocketMessage(jstr.c_str(), jstr.size());
    LOG(INFO) << "msgid: " << jMsg["msgid"].get<ULONG64>() << " send end." << endl;
}

static void dealMessage(DWORD messageAddr)
{
    json jMsg;
    unsigned long long msgid = *(unsigned long long *)(messageAddr + 0x30);
    jMsg["pid"] = GetCurrentProcessId();
    jMsg["type"] = *(DWORD *)(messageAddr + 0x38);
    jMsg["isSendMsg"] = *(BOOL *)(messageAddr + 0x3C);
    if (jMsg["isSendMsg"].get<BOOL>())
    {
        jMsg["isSendByPhone"] = (int)(*(BYTE *)(messageAddr + 0xD8));
    }
    jMsg["msgid"] = msgid;
    // jMsg["localId"] = *(unsigned int *)(messageAddr + 0x20);
    jMsg["sender"] = unicode_to_utf8((wchar_t *)READ_WSTRING(messageAddr, 0x48).c_str());
    int length = *(DWORD *)(messageAddr + 0x170 + 0x4);
    jMsg["wxid"] = length == 0 ? jMsg["sender"].get<std::string>() : unicode_to_utf8((wchar_t *)READ_WSTRING(messageAddr, 0x170).c_str());
    jMsg["message"] = unicode_to_utf8((wchar_t *)READ_WSTRING(messageAddr, 0x70).c_str());
    jMsg["sign"] = unicode_to_utf8((wchar_t *)READ_WSTRING(messageAddr, 0x184).c_str());
    if (jMsg["type"].get<int>() != 10000)
    {
        jMsg["filepath"] = unicode_to_utf8((wchar_t *)READ_WSTRING(messageAddr, 0x1AC).c_str());
        jMsg["thumbnail"] = unicode_to_utf8((wchar_t *)READ_WSTRING(messageAddr, 0x198).c_str());
        jMsg["extrainfo"] = unicode_to_utf8((wchar_t *)READ_WSTRING(messageAddr, 0x1EC).c_str());
    }
    else
    {
        // Ϊ����������˽�����ṩ�ѳ�����Ϣ��ԭ����Ϣ
        jMsg["extrainfo"] = "";
    }
    jMsg["time"] = unicode_to_utf8((wchar_t *)GetTimeW(*(DWORD *)(messageAddr + 0x44)).c_str());
    jMsg["timestamp"] = *(DWORD *)(messageAddr + 0x44);
    jMsg["self"] = unicode_to_utf8((wchar_t *)GetSelfWxid().c_str());
    string jstr = jMsg.dump() + '\n';
    // Ϊ��֤�̰߳�ȫ����Ҫ�ֶ������ڴ�
    SocketMessageStruct *sms = new SocketMessageStruct;
    sms->buffer = new char[jstr.size() + 1];
    memcpy(sms->buffer, jstr.c_str(), jstr.size() + 1);
    sms->length = jstr.size();
    HANDLE hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)SendSocketMessageInThread, sms, NULL, 0);
    if (hThread)
    {
        CloseHandle(hThread);
    }
}

/*
 * ���������ͬ������Ϣ�����˷��ͻ�ʹ���ֻ����͵���Ϣ��
 */
void OnReceiveMessage(DWORD messagesAddr)
{
    DWORD *messages = (DWORD *)messagesAddr;
    for (DWORD messageAddr = messages[0]; messageAddr < messages[1]; messageAddr += 0x298)
    {
        dealMessage(messageAddr);
    }
}

/*
 * �����ط��͵���Ϣ
 */
void OnSendMessage(DWORD messageAddr)
{
    BOOL isSendMsg = *(BOOL *)(messageAddr + 0x3C);
    if (!isSendMsg)
        return;
    dealMessage(messageAddr);
}

/*
 * ������µ���Ϣ��Ŀǰֻ�����ص���Ϣ
 */
void OnUpdateMessage(DWORD messageAddr)
{
    // DWORD type = *(DWORD *)(messageAddr + 0x38);
    dealMessage(messageAddr);
}

/*
 * HOOK�ľ���ʵ�֣����յ���Ϣ����ô�����
 */
_declspec(naked) void dealReceiveMessage()
{
    __asm {
		pushad;
		pushfd;
		push edi;
		call OnReceiveMessage;
		add esp, 0x4;
		popfd;
		popad;
		call ReceiveMessageNextCall;
		jmp ReceiveMessageJmpBackAddress;
    }
}

/*
 * HOOK�ľ���ʵ�֣�������Ϣ����ô�����
 */
_declspec(naked) void dealSendMessage()
{
    __asm {
		pushad;
		pushfd;
		push edi;
		call OnSendMessage;
		add esp, 0x4;
		popfd;
		popad;
		call SendMessageNextCall;
		jmp SendMessageJmpBackAddress;
    }
}

/*
 * HOOK�ľ���ʵ�֣����յ�������Ϣ����ô�����
 */
_declspec(naked) void dealRevokeMessage()
{
    __asm {
		pushad;
		pushfd;
		push edi;
		call OnUpdateMessage;
		add esp, 0x4;
		popfd;
		popad;
		call UpdateMessageNextCall;
		jmp UpdateMessageJmpBackAddress;
    }
}

/*
 * ��ʼ������ϢHOOK
 * return��void
 */
VOID HookReceiveMessage(int port)
{
    SRVPORT = port;
    WeChatWinBase = GetWeChatWinBase();
    if (ReceiveMessageHooked || !WeChatWinBase)
        return;
    ReceiveMessageHookAddress = WeChatWinBase + ReceiveMessageHookOffset;
    ReceiveMessageNextCall = WeChatWinBase + ReceiveMessageNextCallOffset;
    ReceiveMessageJmpBackAddress = ReceiveMessageHookAddress + 0x5;
    SendMessageHookAddress = WeChatWinBase + SendMessageHookOffset;
    SendMessageNextCall = WeChatWinBase + SendMessageNextCallOffset;
    SendMessageJmpBackAddress = SendMessageHookAddress + 0x5;
    UpdateMessageHookAddress = WeChatWinBase + UpdateMessageHookOffset;
    UpdateMessageNextCall = WeChatWinBase + UpdateMessageNextCallOffset;
    UpdateMessageJmpBackAddress = UpdateMessageHookAddress + 0x5;
    HookAnyAddress(ReceiveMessageHookAddress, (LPVOID)dealReceiveMessage, OldReceiveMessageAsmCode);
    HookAnyAddress(SendMessageHookAddress, (LPVOID)dealSendMessage, OldSendMessageAsmCode);
    HookAnyAddress(UpdateMessageHookAddress, (LPVOID)dealRevokeMessage, OldUpdateMessageAsmCode);
    ReceiveMessageHooked = TRUE;
}

/*
 * ֹͣ������ϢHOOK
 * return��void
 */
VOID UnHookReceiveMessage()
{
    SRVPORT = 0;
    if (!ReceiveMessageHooked)
        return;
    UnHookAnyAddress(ReceiveMessageHookAddress, OldReceiveMessageAsmCode);
    UnHookAnyAddress(SendMessageHookAddress, OldSendMessageAsmCode);
    UnHookAnyAddress(UpdateMessageHookAddress, OldUpdateMessageAsmCode);
    ReceiveMessageHooked = FALSE;
}
