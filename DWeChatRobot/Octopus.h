#pragma once

extern "C" __declspec(dllexport) void StartOctopus(const char*);
extern "C" __declspec(dllexport) void StopOctopus();

void ForwardMsg(ReceiveMsgStruct*);