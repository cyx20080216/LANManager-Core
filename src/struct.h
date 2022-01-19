#ifndef STRUCT_H
#define STRUCT_H
#include<shared_mutex>

#include<tins/tins.h>


struct SettingTable
{
    enum ControlType
    {
        Black,
        White
    };
    std::set<Tins::IPv4Address> ipTable;
    ControlType type;
    // uint64_t maxUpload=1073741824;
    // uint64_t maxDownload=1073741824;
};
struct Host
{
    Tins::IPv4Address address;
    Tins::HWAddress<6> HWAddress;
    std::shared_mutex HWAddressMutex;
};
struct Target
{
    Host host;
    SettingTable *settingTable=nullptr;
    // int64_t lastUpload=0;
    // int64_t lastDownload=0;
};
#endif