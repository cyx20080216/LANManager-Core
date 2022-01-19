#ifndef ARPSPOOF_H
#define ARPSPOOF_H
#include<tins/tins.h>


Tins::EthernetII generateARPRequestPacket(const Tins::NetworkInterface &interface,const Tins::IPv4Address &target);
Tins::EthernetII generateARPSpoofPacket(const Tins::NetworkInterface &interface,const Tins::IPv4Address &target,const Tins::HWAddress<6> &targetHW,const Tins::IPv4Address &address);
void sendARPRequestPacket();
void receiveARPResponsePacket();
void sendSpoofPacket();
#endif