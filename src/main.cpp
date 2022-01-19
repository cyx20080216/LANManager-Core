#include<fstream>
#include<thread>
#include<stdint.h>
#include<signal.h>

#include<gflags/gflags.h>
#include<glog/logging.h>
#include<nlohmann/json.hpp>

#include"global.h"
#include"struct.h"
#include"arpspoof.h"
#include"forward.h"


void SIGINTCallback(int signum)
{
    LOG(INFO)<<"Quit.";
    quit=true;
}
DEFINE_string(conf,"config.json","The path of configure file.");
DEFINE_bool(record,false,"Record the packets.");
DECLARE_bool(logtostderr);
DECLARE_int32(stderrthreshold);
DECLARE_string(log_dir);
void initConfigure()
{
    //Open file
    std::fstream configureFile(FLAGS_conf,std::ios::in);
    if(!configureFile)
        LOG(FATAL)<<FLAGS_conf<<" is not exists."<<23;
    //Read file
    char *buffer=new char[65536];
    memset(buffer,0,sizeof(char)*65536);
    configureFile.read(buffer,sizeof(char)*65535);
    if(!configureFile.eof())
        LOG(FATAL)<<FLAGS_conf<<" is bigger than 65536 bytes."<<23;
    //Parse file
    /*
        {
            "interface":"xxx",
            "gateway":"xxx.xxx.xxx.xxx",
            "setting_table":{
                "xxx":{
                    "type":"black/white",
                    "ip":[
                        "xxx.xxx.xxx.xxx",
                        ...
                    ]
                },
                ...
            },
            "target":[
                {
                    "address":"xxx.xxx.xxx.xxx",
                    "setting_table":"xxx"
                },
                ...
            ]
        }
    */
    nlohmann::json configure(nlohmann::json::parse(buffer));
    if(configure.is_null())
        LOG(FATAL)<<"The JSON syntax is wrong.";
    //Set interface
    if(configure.contains("interface"))
        if(configure["interface"].is_string())
            interface=Tins::NetworkInterface(configure["interface"].get<std::string>());
        else
            LOG(FATAL)<<"The interface is not a string.";
    else
        LOG(WARNING)<<"You do not set the intercae.We are going to use default value \"lo\".";
    //Set gateway
    if(configure.contains("gateway"))
        if(configure["gateway"].is_string())
            gateway.address=configure["gateway"].get<std::string>();
        else
            LOG(FATAL)<<"The gateway is not a string.";
    else
        LOG(FATAL)<<"You do not set the gateway.";
    //Set setting tables
    std::map<std::string,SettingTable*> nameAndSettingTable;
    if(configure.contains("setting_table"))
        if(configure["setting_table"].is_object())
        {
            settingTableNum=configure["setting_table"].size();
            settingTable=new SettingTable[settingTableNum];
        }
        else
            LOG(FATAL)<<"The setting_table is not an object.";
    else
        LOG(FATAL)<<"You do not set the setting_table.";
    {
        uint32_t count=0;
        for(nlohmann::json::iterator i=configure["setting_table"].begin();i!=configure["setting_table"].end();++i,count++)
        {
            if(i.value().is_object())
                if(i.value().contains("type"))
                    if(i.value()["type"].is_string())
                        if(std::string(i.value()["type"].get<std::string>())=="black"||\
                        std::string(i.value()["type"].get<std::string>())=="white")
                        {
                            settingTable[count].type=(std::string(i.value()["type"].get<std::string>())=="black"?SettingTable::Black:SettingTable::White);
                            if(i.value().contains("ip"))
                                if(i.value()["ip"].is_array())
                                {
                                    {
                                        uint32_t count2=0;
                                        for(nlohmann::json::iterator j=i.value()["ip"].begin();j!=i.value()["ip"].end();++j,count2++)
                                            if((*j).is_string())
                                                settingTable[count].ipTable.insert((*j).get<std::string>());
                                            else
                                                LOG(FATAL)<<"The object of the "<<count2<<" of the "<<i.key()<<" in the setting_table is not a string.";
                                    }
                                    // if(i.value().contains("max_download"))
                                    //     if(i.value()["max_download"].is_number_unsigned())
                                    //         settingTable[count].maxDownload=i.value()["max_download"].get<uint64_t>();
                                    //     else
                                    //         LOG(FATAL)<<"The max_download of the "<<i.key()<<" in the setting_table is not a interger.";
                                    // else
                                    //     LOG(WARNING)<<"You do not set the max_download of the "<<i.key()<<" in the setting_table.We are going to use the default value 1048576";
                                    // if(i.value().contains("max_upload"))
                                    //     if(i.value()["max_upload"].is_number_unsigned())
                                    //         settingTable[count].maxUpload=i.value()["max_upload"].get<uint64_t>();
                                    //     else
                                    //         LOG(FATAL)<<"The max_upload of the "<<i.key()<<" in the setting_table is not a interger.";
                                    // else
                                    //     LOG(WARNING)<<"You do not set the max_upload of the "<<i.key()<<" in the setting_table.We are going to use the default value 1048576";
                                }
                                else
                                    LOG(FATAL)<<"The ip of the "<<i.key()<<" in the setting_table is not an array.";
                            else
                                LOG(FATAL)<<"You do not set the ip of the "<<i.key()<<" in the setting_table.";
                        }
                        else
                            LOG(FATAL)<<"The value of the type of the "<<i.key()<<" in the setting_table is not \"black\" or \"white\".";
                    else
                        LOG(FATAL)<<"The type of the "<<i.key()<<" in the setting_table is not a string.";
                else
                    LOG(FATAL)<<"You do not set the type of the "<<i.key()<<" in the setting_table.";
            else
                LOG(FATAL)<<"The "<<i.key()<<" in the setting_table is not an object.";
            nameAndSettingTable.insert(std::make_pair(i.key(),settingTable+count));
        }
    }
    //Set targets
    if(configure.contains("target"))
        if(configure["target"].is_array())
        {
            targetNum=configure["target"].size();
            target=new Target[targetNum];
        }
        else
            LOG(FATAL)<<"The target is not an array.";
    else
        LOG(FATAL)<<"You do not set the target.";
    {
        uint32_t count=0;
        for(nlohmann::json::iterator i=configure["target"].begin();i!=configure["target"].end();++i,count++)
        {
            if((*i).is_object())
                if((*i).contains("address"))
                    if((*i)["address"].is_string())
                    {
                        target[count].host.address=(*i)["address"].get<std::string>();
                        ipToTarget.insert(std::make_pair(target[count].host.address.to_string(),target+count));
                        if((*i).contains("setting_table"))
                            if((*i)["setting_table"].is_string())
                                if(nameAndSettingTable.count((*i)["setting_table"].get<std::string>())>0)
                                    target[count].settingTable=nameAndSettingTable.at((*i)["setting_table"].get<std::string>());
                                else
                                    LOG(FATAL)<<"You do not set the "<<(*i)["setting_table"].get<std::string>()<<" of the setting_table.";
                            else
                                LOG(FATAL)<<"The setting_table of the "<<count<<" of the target is not a string.";
                        else
                            LOG(FATAL)<<"You do not set the setting_table of the "<<count<<" in the target.";
                    }
                    else
                        LOG(FATAL)<<"The address of the "<<count<<" of the target is not a string.";
                else
                    LOG(FATAL)<<"You do not set the address of the "<<count<<" in the target.";
            else
                LOG(FATAL)<<"The "<<count<<" of the target is not an object.";
        }
    }
    if(FLAGS_record)
        recorder=new Tins::PacketWriter("record-"+std::to_string(getUS())+".pcap",Tins::DataLinkType<Tins::IP>());
    delete[] buffer;
}
int main(int argc,char **argv)
{
    signal(SIGINT,SIGINTCallback);
    gflags::ParseCommandLineFlags(&argc,&argv,true);
    FLAGS_logtostderr=true;
    google::InitGoogleLogging(argv[0]);
    google::InstallFailureSignalHandler();
    initConfigure();
    LOG(INFO)<<"Finish parsing the configure.";
    std::thread thread1(sendARPRequestPacket);
    std::thread thread2(receiveARPResponsePacket);
    std::thread thread3(sendSpoofPacket);
    std::thread thread4(forwardPacket);
    LOG(INFO)<<"Start";
    while(!quit);
    thread1.join();
    thread2.join();
    thread3.join();
    thread4.join();
    delete recorder;
    delete[] target;
    delete[] settingTable;
}