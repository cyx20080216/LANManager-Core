#ifndef GLOBAL_H
#define GLOBAL_H
#include<string>
#include<map>

#include<tins/tins.h>

#include"struct.h"


int64_t getUS();
extern bool quit;
extern Tins::PacketWriter *recorder;
extern Tins::NetworkInterface interface;
extern Host gateway;
extern uint32_t settingTableNum;
extern SettingTable *settingTable;
extern uint32_t targetNum;
extern Target *target;
extern std::map<std::string,Target*> ipToTarget;
#endif