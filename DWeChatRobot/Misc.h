#pragma once

struct WxUser {
	std::string id;
	std::string nickName;
	std::string remark;
};

WxUser GetSelf();
WxUser GetUserInfo(wchar_t*);
std::vector<WxUser> GetFriends();
std::wstring GetFileSavePath();

const std::string gen_uuid();
bool ends_with(const std::string&, const std::string&);
const std::string read_file(const std::string&);
BOOL write_file(const std::string&, const std::string&);
const std::string download_file(const std::string&);
const std::string as_utf8(const std::wstring&);
const std::string as_utf8(const wchar_t*);
const std::wstring as_wide(const std::string&);