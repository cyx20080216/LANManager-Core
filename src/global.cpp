#include"global.h"

#include<ctime>


int64_t getUS()
{
    struct timeval t;
    gettimeofday(&t, 0);
    return static_cast<int64_t>(t.tv_sec)*1000000+t.tv_usec;
}
bool quit(false);
Tins::PacketWriter *recorder(nullptr);
Tins::NetworkInterface interface("lo");
Host gateway;
uint32_t settingTableNum(0);
SettingTable *settingTable(nullptr);
uint32_t targetNum(0);
Target *target(nullptr);
std::map<std::string,Target*> ipToTarget;