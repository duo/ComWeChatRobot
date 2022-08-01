#include "pch.h"
#include "Octopus.h"

#include "misc.h"

#include "mongoose/mongoose.c"
#include "nlohmann/json.hpp"
#include "pugixml/pugixml.hpp"
#include "pugixml/pugixml.cpp"
#include "proto/octopus.pb.h"
#include "proto/octopus.pb.cc"

#include <queue>


#define RETRY_MAX 200

#pragma comment (lib, "rpcrt4.lib")

using octopus::Payload;
using octopus::Vendor;
using octopus::User;
using octopus::Message;
using octopus::Chat;
using octopus::Photo;
using octopus::Payload_PayloadType;
using octopus::Chat_ChatType;
using octopus::Message_MessageType;

using json = nlohmann::json;

size_t write_data2(void* contents, size_t size, size_t nmemb, void* userp) {
    ((std::string*)userp)->append((char*)contents, size * nmemb);
    return size * nmemb;
}

class Octopus {
public:
    static Octopus& getInstance() {
        static Octopus instance;
        return instance;
    }

    Octopus(Octopus const&) = delete;
    void operator=(Octopus const&) = delete;

    void Forward(ReceiveMsgStruct*);

    void Start(const char* conf);
    void Stop();

    // Avoid crash, any good solution?
    static DWORD WINAPI DelayUploadChats(void* param) {
        Octopus* obj = (Octopus*)param;
        Sleep(10000);
        obj->UploadChats();
        return 0;
    };

private:
    Octopus() {}
    ~Octopus() {}

    void WebsocketThread();

    static void Connect(void*);
    static void OnEvent(struct mg_connection*, int, void*, void*);

    void UploadChats();
    void Deliver(const Payload&);

    std::string addr_;
    std::wstring workdir_;
    std::wstring tempdir_;
    std::wstring imagedir_;
    std::wstring voicedir_;
    std::vector<std::string> blacklist_;

    std::queue<Payload> q_;
    std::mutex mtx_;

    mg_mgr mgr_;
    struct mg_connection* client_;

    std::atomic_bool running_;
    std::thread ws_thread_;
};

void Octopus::WebsocketThread() {
    mg_mgr_init(&mgr_);

    mg_timer_add(&mgr_, 3000, MG_TIMER_REPEAT | MG_TIMER_RUN_NOW, Octopus::Connect, this);

    int retry_count = 0;
    while (running_) {
        mg_mgr_poll(&mgr_, 100);

        if (client_ != NULL) {
            std::lock_guard<std::mutex> lck(mtx_);
            while (!q_.empty()) {
                Payload payload = q_.front();

                if (payload.message().type() == Message_MessageType::Message_MessageType_PHOTO) {
                    const std::string path = payload.message().photos().Get(0).bin().md5();
                    const std::string content = read_file(path);
                    if (content.empty()) {
                        if (++retry_count < RETRY_MAX) {
                            break;
                        } else {
                            retry_count = 0;
                            payload.mutable_message()->set_type(Message_MessageType::Message_MessageType_TEXT);
                            payload.mutable_message()->set_text(as_utf8(L"[Í¼Æ¬±£´æÊ§°Ü]"));
                        }
                    } else {
                        payload.mutable_message()->mutable_photos()->Clear();
                        payload.mutable_message()->mutable_text()->clear();
                        payload.mutable_message()->add_photos()->mutable_bin()->set_blob(content);
                    }
                } else if (payload.message().type() == Message_MessageType::Message_MessageType_VIDEO) {
                    const std::string path = payload.message().video().bin().md5();
                    const std::string content = read_file(path);
                    if (content.empty()) {
                        if (++retry_count < RETRY_MAX) {
                            break;
                        }
                        else {
                            retry_count = 0;
                            payload.mutable_message()->set_type(Message_MessageType::Message_MessageType_TEXT);
                            payload.mutable_message()->set_text(as_utf8(L"[ÊÓÆµ±£´æÊ§°Ü]"));
                        }
                    } else {
                        payload.mutable_message()->mutable_video()->mutable_bin()->set_blob(content);
                    }
                } else if (payload.message().type() == Message_MessageType::Message_MessageType_VOICE) {
                    const std::string path = payload.message().voice().bin().md5();
                    const std::string content = read_file(path);
                    if (content.empty()) {
                        if (++retry_count < RETRY_MAX) {
                            break;
                        }
                        else {
                            retry_count = 0;
                            payload.mutable_message()->set_type(Message_MessageType::Message_MessageType_TEXT);
                            payload.mutable_message()->set_text(as_utf8(L"[ÓïÒô±£´æÊ§°Ü]"));
                        }
                    }
                    else {
                        payload.mutable_message()->mutable_voice()->mutable_bin()->set_blob(content);
                    }
                } else if (payload.message().type() == Message_MessageType::Message_MessageType_FILE) {
                    const std::string path = payload.message().file().name();
                    const std::string content = read_file(path);
                    if (content.empty()) {
                        if (++retry_count < RETRY_MAX) {
                            break;
                        }
                        else {
                            retry_count = 0;
                            payload.mutable_message()->set_type(Message_MessageType::Message_MessageType_TEXT);
                            payload.mutable_message()->set_text(as_utf8(L"[ÎÄ¼þ±£´æÊ§°Ü]"));
                        }
                    } else {
                        payload.mutable_message()->mutable_file()->mutable_bin()->set_blob(content);
                        int pos_begin = path.find_last_of("\\") + 1;
                        const std::string filename = path.substr(pos_begin, path.size() - pos_begin);
                        payload.mutable_message()->mutable_file()->set_name(filename);
                    }
                } else if (payload.message().type() == Message_MessageType::Message_MessageType_STICKER) {
                    const std::string text = payload.message().text();
                    std::string content;
                    pugi::xml_document doc;
                    pugi::xml_parse_result result = doc.load_buffer(text.c_str(), text.size());
                    if (result) {
                        pugi::xpath_node node = doc.select_node(PUGIXML_TEXT("/msg/emoji"));
                        if (node) {
                            content = download_file(pugi::as_utf8(node.node().attribute(PUGIXML_TEXT("cdnurl")).value()));
                        }
                    }
                    if (content.empty()) {
                        payload.mutable_message()->set_type(Message_MessageType::Message_MessageType_TEXT);
                        payload.mutable_message()->set_text(as_utf8(L"[±íÇé±£´æÊ§°Ü]"));
                    } else {
                        payload.mutable_message()->mutable_text()->clear();
                        payload.mutable_message()->mutable_sticker()->mutable_bin()->set_blob(content);
                    }
                }

                q_.pop();

                size_t size = payload.ByteSizeLong();
                void* buffer = malloc(size);
                payload.SerializeToArray(buffer, size);
                mg_ws_send(client_, (const char*)buffer, size, WEBSOCKET_OP_BINARY);
                free(buffer);
            }
        }
    }

    mg_mgr_free(&mgr_);
}

void Octopus::Connect(void* fn_data) {
    Octopus* octopus = (Octopus*)fn_data;
    if (octopus->client_ == NULL) {
        octopus->client_ = mg_ws_connect(&octopus->mgr_, octopus->addr_.c_str(), Octopus::OnEvent, octopus, NULL);
    }
}

void Octopus::OnEvent(struct mg_connection* c, int ev, void* ev_data, void* fn_data) {
    if (ev == MG_EV_OPEN) {
        MG_INFO(("CREATED"));
    } else if (ev == MG_EV_ERROR) {
        MG_ERROR(("%p %s", c->fd, (char*)ev_data));
        c->is_closing = 1;
    } else if (ev == MG_EV_WS_OPEN) {
        MG_INFO(("CONNECTED to %s", ((Octopus*)fn_data)->addr_.c_str()));
        HANDLE hThread = CreateThread(NULL, 0, Octopus::DelayUploadChats, fn_data, NULL, 0);
        if (hThread) {
            CloseHandle(hThread);
        }
        //((Octopus*)fn_data)->UploadChats();
    } else if (ev == MG_EV_WS_MSG) {
        struct mg_ws_message* wm = (struct mg_ws_message*)ev_data;
        Payload payload;
        payload.ParseFromArray(wm->data.ptr, wm->data.len);
        ((Octopus*)fn_data)->Deliver(payload);
        c->recv.len = 0;
    } else if (ev == MG_EV_CLOSE) {
        MG_INFO(("CLOSED"));
        ((Octopus*)fn_data)->client_ = NULL;
    }
}

void Octopus::UploadChats() {
    Payload payload;

    WxUser me = GetSelf();

    payload.mutable_vendor()->set_uid(me.id);
    payload.mutable_vendor()->set_type("wechat");

    payload.set_uid(gen_uuid());
    payload.set_type(Payload_PayloadType::Payload_PayloadType_CHATS);

    std::vector<WxUser> friends = GetFriends();
    friends.insert(friends.begin(), me);

    for (WxUser user : friends) {
        Chat* chat = payload.add_chats();
        chat->set_uid(user.id);
        chat->set_title(user.remark);
        if (ends_with(user.id, "@chatroom")) {
            chat->set_type(Chat_ChatType::Chat_ChatType_GROUP);
        } else {
            chat->set_type(Chat_ChatType::Chat_ChatType_PRIVATE);
        }
    }
    friends.clear();

    std::lock_guard<std::mutex> lck(mtx_);
    q_.push(payload);
}

void Octopus::Deliver(const Payload& payload) {
    if (payload.type() != Payload_PayloadType::Payload_PayloadType_MESSAGE) {
        return;
    }

    std::wstring to = as_wide(payload.message().chat().uid());
    switch (payload.message().type()) {
    case Message_MessageType::Message_MessageType_TEXT: {
        SendText((wchar_t*)to.c_str(), (wchar_t*)as_wide(payload.message().text()).c_str());
        break;
    }
    case Message_MessageType::Message_MessageType_PHOTO: {
        for (Photo photo : payload.message().photos()) {
            std::string path = as_utf8(this->tempdir_) + photo.bin().md5();
            if (write_file(path, photo.bin().blob())) {
                SendImage((wchar_t*)to.c_str(), (wchar_t*)as_wide(path).c_str());
            }
        }
        break;
    }
    case Message_MessageType::Message_MessageType_STICKER: {
        std::string path = as_utf8(this->tempdir_) + payload.message().sticker().bin().md5();
        if (write_file(path, payload.message().sticker().bin().blob())) {
            SendImage((wchar_t*)to.c_str(), (wchar_t*)as_wide(path).c_str());
        }
        break;
    }
    case Message_MessageType::Message_MessageType_VIDEO: {
        std::string path = as_utf8(this->tempdir_) + payload.message().video().bin().md5();
        if (payload.message().video().bin().mime() == "video/mp4") {
            path += ".mp4";
        }
        if (write_file(path, payload.message().video().bin().blob())) {
            SendImage((wchar_t*)to.c_str(), (wchar_t*)as_wide(path).c_str());
        }
        break;
    }
    case Message_MessageType::Message_MessageType_FILE: {
        std::string path = as_utf8(this->tempdir_) + payload.message().file().name();
        if (write_file(path, payload.message().file().bin().blob())) {
            SendFile((wchar_t*)to.c_str(), (wchar_t*)as_wide(path).c_str());
        }
        break;
    }
    default:
        break;
    }
}

void Octopus::Forward(ReceiveMsgStruct* msg) {
    std::string sender = as_utf8(msg->sender);

    if (std::find(blacklist_.begin(), blacklist_.end(), sender) != blacklist_.end()) {
        delete msg;
        return;
    }

    Payload payload;

    WxUser me = GetSelf();

    payload.mutable_vendor()->set_uid(me.id);
    payload.mutable_vendor()->set_type("wechat");

    payload.set_uid(gen_uuid());
    payload.set_type(Payload_PayloadType::Payload_PayloadType_MESSAGE);

    Message* message = payload.mutable_message();
    Chat* chat = message->mutable_chat();

    message->set_message_id(msg->srvid);
    message->set_date(msg->timestamp);

    WxUser senderInfo = GetUserInfo(msg->sender);
    WxUser wxInfo = GetUserInfo(msg->wxid);

    if (ends_with(sender, "@chatroom")) {
        chat->set_type(Chat_ChatType::Chat_ChatType_GROUP);
    }
    else {
        chat->set_type(Chat_ChatType::Chat_ChatType_PRIVATE);
    }
    chat->set_uid(sender);
    chat->set_title(senderInfo.nickName);
    if (msg->isSendMessage) {
        message->mutable_from()->set_uid(me.id);
        message->mutable_from()->set_username(me.nickName);
        message->mutable_from()->set_remark(me.remark);
    }
    else {
        message->mutable_from()->set_uid(wxInfo.id);
        message->mutable_from()->set_username(wxInfo.nickName);
        message->mutable_from()->set_remark(wxInfo.remark);
        if (ends_with(sender, "@chatroom")) {
            std::wstring nickName = GetChatRoomMemberNickname(msg->sender, msg->wxid);
            message->mutable_from()->set_username(as_utf8(nickName));
            message->mutable_from()->set_remark(as_utf8(nickName));
        }
    }

    message->set_text(as_utf8(msg->message));
    message->set_type(Message_MessageType::Message_MessageType_TEXT);

    switch (msg->messagetype) {
    case 0x3: { // image
        std::wstring wdatpath(msg->filepath);
        int pos_begin = wdatpath.find_last_of(L"\\") + 1;
        int pos_end = wdatpath.find_last_of(L".");
        wstring filename = wdatpath.substr(pos_begin, pos_end - pos_begin);
        std::wstring path = this->imagedir_ + filename;

        message->set_type(Message_MessageType::Message_MessageType_PHOTO);
        message->add_photos()->mutable_bin()->set_md5(as_utf8(path));
        break;
    }
    case 0x22: { // voice
        std::string text = message->text();
        pugi::xml_document doc;
        pugi::xml_parse_result result = doc.load_buffer(text.c_str(), text.size());
        if (result) {
            pugi::xpath_node voice_node = doc.select_node(PUGIXML_TEXT("/msg/voicemsg"));
            if (!voice_node) {
                break;
            }

            std::wstring from = voice_node.node().attribute(PUGIXML_TEXT("fromusername")).value();
            std::wstring msgid = voice_node.node().attribute(PUGIXML_TEXT("clientmsgid")).value();
            std::wstring path = this->voicedir_ + from + L"-" + msgid + L".amr";

            message->set_type(Message_MessageType::Message_MessageType_VOICE);
            message->mutable_voice()->mutable_bin()->set_md5(as_utf8(path));
        }
        break;
    }
    case 0x2B: { //video
        std::wstring wdatpath(msg->thumbpath);
        int pos_end = wdatpath.find_last_of(L".");
        wstring filename = wdatpath.substr(0, pos_end) + L".mp4";
        std::wstring path = workdir_ + filename;

        message->set_type(Message_MessageType::Message_MessageType_VIDEO);
        message->mutable_video()->mutable_bin()->set_md5(as_utf8(path));
        break;
    }
    case 0x2F: {
        message->set_type(Message_MessageType::Message_MessageType_STICKER);
        break;
    }
    case 0x30: { // location
        std::string text = message->text();
        pugi::xml_document doc;
        pugi::xml_parse_result result = doc.load_buffer(text.c_str(), text.size());
        if (result) {
            pugi::xpath_node loc_node = doc.select_node(PUGIXML_TEXT("/msg/location"));
            if (!loc_node) {
                break;
            }

            double x = loc_node.node().attribute(PUGIXML_TEXT("x")).as_double();
            double y = loc_node.node().attribute(PUGIXML_TEXT("y")).as_double();

            message->set_type(Message_MessageType::Message_MessageType_LOCATION);
            message->mutable_location()->set_latitude(x);
            message->mutable_location()->set_longitude(y);
        }
    }
    case 0x31: {
        std::string text = message->text();
        pugi::xml_document doc;
        pugi::xml_parse_result result = doc.load_buffer(text.c_str(), text.size());
        if (result) {
            pugi::xpath_node type_node = doc.select_node(PUGIXML_TEXT("/msg/appmsg/type"));
            if (!type_node) {
                break;
            }

            int type = type_node.node().text().as_int();
            switch (type) {
            case 0x6: { // file
                message->set_type(Message_MessageType::Message_MessageType_FILE);
                message->mutable_file()->set_name(as_utf8(workdir_ + msg->filepath));
                break;
            }
            case 0x39: { // ref
                std::wstring content;
                std::wstring reply;

                pugi::xpath_node title_node = doc.select_node(PUGIXML_TEXT("/msg/appmsg/title"));
                if (title_node) {
                    content += title_node.node().text().as_string();
                }

                reply += L"\n- - - - - - - - - - - - - - -\n¡¸";

                pugi::xpath_node name_node = doc.select_node(PUGIXML_TEXT("/msg/appmsg/refermsg/displayname"));
                if (name_node) {
                    reply += name_node.node().text().as_string();
                    reply += L"£º";
                }

                pugi::xpath_node ref_type_node = doc.select_node(PUGIXML_TEXT("/msg/appmsg/refermsg/type"));
                if (ref_type_node) {
                    int ref_type = ref_type_node.node().text().as_int();
                    switch (ref_type) {
                    case 0x1: {
                        pugi::xpath_node content_node = doc.select_node(PUGIXML_TEXT("/msg/appmsg/refermsg/content"));
                        if (content_node) {
                            reply += content_node.node().text().as_string();
                        }
                        break;
                    }
                    case 0x3:
                        reply += L"[Í¼Æ¬]";
                        break;
                    case 0x22:
                        reply += L"[ÓïÒô]";
                        break;
                    case 0x2B:
                        reply += L"[ÊÓÆµ]";
                        break;
                    case 0x2F:
                        reply += L"[±íÇé]";
                        break;
                    case 0x30:
                        reply += L"[Î»ÖÃ]";
                        break;
                    case 0x31:
                        reply += L"[³ÌÐò]";
                        break;
                    default:
                        break;
                    }
                }

                reply += L"¡¹";

                pugi::xpath_node srvid_node = doc.select_node(PUGIXML_TEXT("/msg/appmsg/refermsg/svrid"));
                if (srvid_node) {
                    Message* replyMessage = message->mutable_reply_to_message();
                    replyMessage->set_message_id(srvid_node.node().text().as_ullong());
                    replyMessage->set_text(as_utf8(reply));
                }

                if (message->has_reply_to_message()) {
                    message->set_text(as_utf8(content));
                }
                else {
                    message->set_text(as_utf8(content + reply));
                }

                break;
            }
            default:
                pugi::xpath_node title_node = doc.select_node(PUGIXML_TEXT("/msg/appmsg/title"));
                pugi::xpath_node url_node = doc.select_node(PUGIXML_TEXT("/msg/appmsg/url"));
                pugi::xpath_node des_node = doc.select_node(PUGIXML_TEXT("/msg/appmsg/des"));

                if (!title_node || !url_node) {
                    break;
                }

                message->set_type(Message_MessageType::Message_MessageType_LINK);
                message->mutable_link()->set_title(pugi::as_utf8(title_node.node().text().as_string()));
                message->mutable_link()->set_url(pugi::as_utf8(url_node.node().text().as_string()));
                message->mutable_link()->set_description(pugi::as_utf8(des_node.node().text().as_string()));

                //std::cout << "type: " << type << std::endl << message->text() << std::endl;
                break;
            }            
        }
        break;
    }
    default:
        break;
    }

    std::lock_guard<std::mutex> lck(mtx_);
    q_.push(payload);

    delete msg;
}

void Octopus::Start(const char* conf) {
    if (running_) {
        return;
    }

    //CreateConsole();

    json data = json::parse(conf);
    this->addr_ = data["host"];
    
    for (std::string elem : data["blacklist"]) {
        std::cout << "Add " << elem << " to blacklist." << std::endl;
        this->blacklist_.push_back(elem);
    }

    this->workdir_ = GetFileSavePath();
    this->tempdir_ = this->workdir_ + L"Temp\\";
    this->imagedir_ = this->workdir_ + L"Image\\";
    this->voicedir_ = this->workdir_ + L"Voice\\";

    if (!FindOrCreateDirectory(this->tempdir_.substr(0, this->tempdir_.length() - 1).c_str())) {
        return;
    }

    HookImageMsgRemote((LPVOID)this->imagedir_.c_str());
    HookVoiceMsgRemote((LPVOID)this->voicedir_.c_str());
    HookReceiveMessage(0);

    running_ = true;
    ws_thread_ = std::thread(&Octopus::WebsocketThread, this);
}

void Octopus::Stop() {
    if (!running_) {
        return;
    }

    running_ = false;
    if (ws_thread_.joinable()) {
        ws_thread_.join();
    }
}

void StartOctopus(const char* conf) {
    Octopus::getInstance().Start(conf);
}

void StopOctopus() {
    Octopus::getInstance().Stop();
}

void ForwardMsg(ReceiveMsgStruct* msg) {
    Octopus::getInstance().Forward(msg);
}