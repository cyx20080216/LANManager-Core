#include"forward.h"

#include<sys/ioctl.h>
#include<net/if.h>

#include<glog/logging.h>

#include"global.h"

#define CEIL_DIV(A,B) ((A)%(B)==0?(A)/(B):(A)/(B)+1)


int getInterfaceMTU(const std::string &interfaceName)
{
    int fd = socket(AF_INET,SOCK_DGRAM,0);
    struct ifreq ifr;
    strncpy(ifr.ifr_name,interfaceName.c_str(),IFNAMSIZ-1);
    if (ioctl(fd,SIOCGIFMTU,&ifr)) {
        perror("ioctl");
        return 1;
    }
    close(fd);
    return ifr.ifr_mtu;
}
void forwardPacket()
{
    int mtu=getInterfaceMTU(interface.name());
    Tins::PacketSender sender;
    Tins::SnifferConfiguration configuration;
    configuration.set_timeout(1);
    configuration.set_pcap_sniffing_method([](pcap_t *p,int cnt,pcap_handler callback,u_char *user)->int
    {
        int re=pcap_dispatch(p,cnt,callback,user);
        return re==0?-1:re;
    });
    configuration.set_filter("ether dst "+interface.hw_address().to_string()+" and ip"+" and not ip dst "+interface.ipv4_address().to_string());
    Tins::Sniffer sniffer(interface.name(),configuration);
    pcap_setnonblock(sniffer.get_pcap_handle(),1,nullptr);
    while(!quit)
    {
        Tins::PDU *packet=sniffer.next_packet();
        if(packet==nullptr)
            continue;
        if(ipToTarget.count(packet->find_pdu<Tins::IP>()->src_addr().to_string())>0)
        {
            if(packet->find_pdu<Tins::IP>()->dst_addr()==gateway.address||(packet->find_pdu<Tins::IP>()->dst_addr()&interface.ipv4_mask())!=(interface.ipv4_address()&interface.ipv4_mask()))
            {
                Target *target=ipToTarget.at(packet->find_pdu<Tins::IP>()->src_addr().to_string());
                if(target->settingTable->type==SettingTable::Black)
                {
                    if(target->settingTable->ipTable.count(packet->find_pdu<Tins::IP>()->dst_addr())<=0)
                        goto forward;
                }
                else
                {
                    if(target->settingTable->ipTable.count(packet->find_pdu<Tins::IP>()->dst_addr())>0)
                        goto forward;
                }
            }
        }
        else if(ipToTarget.count(packet->find_pdu<Tins::IP>()->dst_addr().to_string())>0)
        {
            if(packet->find_pdu<Tins::IP>()->src_addr()==gateway.address||(packet->find_pdu<Tins::IP>()->src_addr()&interface.ipv4_mask())!=(interface.ipv4_address()&interface.ipv4_mask()))
            {
                Target *target=ipToTarget.at(packet->find_pdu<Tins::IP>()->dst_addr().to_string());
                if(target->settingTable->type==SettingTable::Black)
                {
                    if(target->settingTable->ipTable.count(packet->find_pdu<Tins::IP>()->src_addr())<=0)
                        goto forward;
                }
                else
                {
                    if(target->settingTable->ipTable.count(packet->find_pdu<Tins::IP>()->src_addr())>0)
                        goto forward;
                }
            }
        }
        goto donot_forward;
        forward:
            try
            {
                if(recorder!=nullptr)
                    recorder->write(*packet->find_pdu<Tins::IP>());
                sender.send(*packet->find_pdu<Tins::IP>());
            }
            catch(Tins::socket_write_error error)
            {
                // if(packet->find_pdu<Tins::TCP>()!=nullptr&&packet->find_pdu<Tins::RawPDU>()!=nullptr&&packet->find_pdu<Tins::TCP>()->flags()&(Tins::TCP::SYN|Tins::TCP::FIN|Tins::TCP::RST)==0&&mtu>packet->find_pdu<Tins::IP>()->header_size()+packet->find_pdu<Tins::TCP>()->header_size())
                // {
                //     uint16_t maxSize=mtu-packet->find_pdu<Tins::IP>()->header_size()-packet->find_pdu<Tins::TCP>()->header_size();
                //     std::vector<std::vector<uint8_t> > dataSeg;
                //     std::vector<uint8_t> data=packet->find_pdu<Tins::RawPDU>()->payload();
                //     for(std::vector<uint8_t>::const_iterator i=data.begin();i!=data.end();i++)
                //     {
                //         if(dataSeg.empty()||dataSeg.back().size()>=maxSize)
                //             dataSeg.push_back(std::vector<uint8_t>());
                //         dataSeg.back().push_back(*i);
                //     }
                //     uint32_t seq=packet->find_pdu<Tins::TCP>()->seq();
                //     for(std::vector<std::vector<uint8_t> >::const_iterator i=dataSeg.begin();i!=dataSeg.end();i++)
                //     {
                //         Tins::IP segPacket=(*packet->find_pdu<Tins::IP>())/(*packet->find_pdu<Tins::TCP>())/Tins::RawPDU(*i);
                //         segPacket.find_pdu<Tins::TCP>()->seq(seq);
                //         LOG(INFO)<<segPacket.size();
                //         sender.send(segPacket);
                //         seq+=maxSize;
                //     }
                // }
            }
        donot_forward:;
        delete packet;
    }
}