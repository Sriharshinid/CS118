/* -*- Mode:C++; c-file-style:"gnu"; indent-tabs-mode:nil; -*- */
/**
 * Copyright (c) 2017 Alexander Afanasyev
 *
 * This program is free software: you can redistribute it and/or modify it under the terms of
 * the GNU General Public License as published by the Free Software Foundation, either version
 * 3 of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY;
 * without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with this program.
 * If not, see <http://www.gnu.org/licenses/>.
 */

#include "simple-router.hpp"
#include "core/utils.hpp"

#include <fstream>

namespace simple_router {

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////
// IMPLEMENT THIS METHOD
void SimpleRouter::handleARP(const Buffer& packet, const Interface* iface) {
  arp_hdr* arp_head = (arp_hdr*) (&packet[0] + sizeof(ethernet_hdr));

  // std::cerr << "Printing ARP header: " << std::endl;
  // print_hdr_arp((uint8_t*)arp_head);

  std::cerr << "Here is the opcode: "<< ntohs(arp_head->arp_op) << std::endl;
  if(ntohs(arp_head->arp_op) == arp_op_request) {
    //arp request packet
    std::cerr << "This was an ARP request" << std::endl;

    //now we must prepare the response
    if(arp_head->arp_tip != iface->ip) {
      std::cerr << "This ARP request is not for me!!" << std::endl;
      return;
    }

    //prep ARP response packet
    Buffer newARP(sizeof(arp_hdr) + sizeof(ethernet_hdr));
    ethernet_hdr* newPacketEth = (ethernet_hdr*)((uint8_t*)newARP.data());
    arp_hdr* newPacketArp = (arp_hdr*)((uint8_t*)newARP.data() + sizeof(ethernet_hdr));

    memcpy(newPacketEth->ether_dhost, &((arp_head->arp_sha)[0]), ETHER_ADDR_LEN);
    memcpy(newPacketEth->ether_shost, (iface->addr).data(), ETHER_ADDR_LEN);
    newPacketEth->ether_type = htons(ethertype_arp);


    newPacketArp->arp_hrd = htons(arp_hrd_ethernet);
    newPacketArp->arp_pro = htons(ethertype_ip);
    newPacketArp->arp_op = htons(arp_op_reply);
    newPacketArp->arp_hln = 0x06;
    newPacketArp->arp_pln = 0x04;

    memcpy(newPacketArp->arp_sha, (iface->addr).data(), ETHER_ADDR_LEN);
    memcpy(newPacketArp->arp_tha, &((arp_head->arp_sha)[0]), ETHER_ADDR_LEN);

    newPacketArp->arp_sip = iface->ip;
    newPacketArp->arp_tip = arp_head->arp_sip;

    print_hdr_arp((uint8_t*)(newPacketArp));
    sendPacket(newARP, iface->name);

  } else if(ntohs(arp_head->arp_op) == arp_op_reply) {
    std::cerr <<"This was an ARP response" << std::endl;

    //record IP-MAC mapping in ARP ArpCache
    Buffer mac_addr(ETHER_ADDR_LEN);
    uint32_t srcIp = arp_head->arp_sip;
    memcpy(mac_addr.data(), arp_head->arp_sha, ETHER_ADDR_LEN);

    std::shared_ptr<ArpRequest> req = m_arp.insertArpEntry(mac_addr, srcIp);

    //sned out all corresponding enqueued packets for ARP entry
    if(req) {
      std::list<PendingPacket>::const_iterator it = req->packets.begin();
      while(it != req->packets.end()) {
        const uint8_t* packetData = it->packet.data();
        ethernet_hdr* eH = (ethernet_hdr*)packetData;
        ip_hdr* ipH = (ip_hdr*)(packetData + sizeof(ethernet_hdr));
        memcpy(eH->ether_shost, iface->addr.data(), ETHER_ADDR_LEN);
        memcpy(eH->ether_dhost, arp_head->arp_sha, ETHER_ADDR_LEN);

        //decrement TTl and recalculate checksum
        ipH->ip_ttl = ipH->ip_ttl - 1;
        ipH->ip_sum = 0;
        ipH->ip_sum = cksum(ipH, sizeof(ip_hdr));

        //send
        sendPacket(it->packet, it->iface);
        print_hdrs(it->packet.data(), it->packet.size());
        ++it;
      }
      m_arp.removeRequest(req);
    }
  } else {
    std::cerr<< "Invalid op code." << std::endl;
    return;
  }
}


void SimpleRouter::handleIP(const Buffer& packet, const Interface* iface) {
  std::cerr << "In IP handler !!!!!" << std::endl;
  //4.
  Buffer packetTOSend(packet);
  ip_hdr* ipH = (ip_hdr*)(packetTOSend.data() + sizeof(ethernet_hdr));

    //a. verify checksum and min length and discard all invalids
  uint16_t check = ipH->ip_sum;
  ipH->ip_sum = 0;
  if(check != cksum(ipH, sizeof(ip_hdr))) {
    std::cerr << "Invalid checksum." << std::endl;
    return;
  }

  if(packetTOSend.size() < sizeof(ethernet_hdr) + sizeof(ip_hdr) || ipH->ip_len < sizeof(ip_hdr)) {
    std::cerr << "Too small." << std::endl;
    return;
  }

    //b.if packet is supposed to go to the router discard it
  std::set<Interface>::const_iterator it = m_ifaces.begin();
  while( it != m_ifaces.end() ) {
    if(it->ip == ipH->ip_dst) {
      std::cerr << "Packet destination is the router" << std::endl;
      return;
    }
    ++it;
  }

    //decrement TTL and recompute checksum
  if(ipH->ip_ttl < 0) {
    std::cerr << "Exceeded TTL :(" << std::endl;
    return;
  }

  std::cerr << "FORWARDING PACKET" << std::endl;
  ipH->ip_ttl = ipH->ip_ttl - 1;
  ipH->ip_sum = cksum(ipH, sizeof(ip_hdr));

  //use longest prefix match algo to find next hop IP addr in routing table
  RoutingTableEntry Rentry = m_routingTable.lookup(ipH->ip_dst);

  //check ARP chache for MAC addr to next hop
  std::shared_ptr<ArpEntry> Aentry = m_arp.lookup(ipH->ip_dst);
  const Interface* ifce = findIfaceByName(Rentry.ifName);

  if(Aentry) {
    //valid entry found proceed with handling IP packet
    ethernet_hdr* eH = (ethernet_hdr*)packetTOSend.data();
    memcpy(eH->ether_dhost, Aentry->mac.data() , ETHER_ADDR_LEN);
    memcpy(eH->ether_shost, ifce->addr.data(), ETHER_ADDR_LEN);
    eH->ether_type = htons(ethertype_ip);

    sendPacket(packetTOSend, ifce->name);

  } else {
    // queue recieved packet and send ARP request
    m_arp.queueRequest(ipH->ip_dst, packetTOSend, ifce->name );

    Buffer newARP(sizeof(ethernet_hdr) + sizeof(arp_hdr));

    ethernet_hdr* newPacketEth = (ethernet_hdr*)((uint8_t*)newARP.data());
    arp_hdr* newPacketArp = (arp_hdr*)((uint8_t*)newARP.data() + sizeof(ethernet_hdr));

    memcpy(newPacketEth->ether_dhost, BroadcastEtherAddr, ETHER_ADDR_LEN);
    memcpy(newPacketEth->ether_shost, ifce->addr.data(), ETHER_ADDR_LEN);
    newPacketEth->ether_type = htons(ethertype_arp);


    newPacketArp->arp_hrd = htons(arp_hrd_ethernet);
    newPacketArp->arp_pro = htons(ethertype_ip);
    newPacketArp->arp_op = htons(arp_op_request);
    newPacketArp->arp_hln = 0x06;
    newPacketArp->arp_pln = 0x04;

    memcpy(newPacketArp->arp_sha, ifce->addr.data(), ETHER_ADDR_LEN);
    memcpy(newPacketArp->arp_tha, BroadcastEtherAddr, ETHER_ADDR_LEN);

    newPacketArp->arp_sip = ifce->ip;
    newPacketArp->arp_tip = ipH->ip_dst;

    std::cerr << "\n\n";
    print_hdrs(newARP.data(), newARP.size());

    sendPacket(newARP, ifce->name);
  }
}

void
SimpleRouter::handlePacket(const Buffer& packet, const std::string& inIface)
{
  std::cerr << "Got packet of size " << packet.size() << " on interface " << inIface << std::endl;

  const Interface* iface = findIfaceByName(inIface);
  if (iface == nullptr) {
    std::cerr << "Received packet, but interface is unknown, ignoring" << std::endl;
    return;
  }

  std::cerr << getRoutingTable() << std::endl;

  //2. Read the ethernet header and check the type field ignore all types other than ARP or IPv4
    //cast the Buffer as an ethernet header struct
    //check type field
  ethernet_hdr ether_header;
  memcpy(&ether_header, &packet[0], sizeof(ether_header));

  uint16_t eth_type = ethertype((const uint8_t*)packet.data());

  switch(eth_type) {
    case ethertype_arp:
      std::cerr << "ARP Packet" << std::endl;
      //handle arp requests
      handleARP(packet, iface);
      break;
    case ethertype_ip:
      std::cerr << "IP Packet" << std::endl;
      //handle Ip packets
      handleIP(packet, iface);
      break;
    default:
      std::cerr << "None of the valid headers" << std::endl;
      return;
  }


}
//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

// You should not need to touch the rest of this code.
SimpleRouter::SimpleRouter()
  : m_arp(*this)
{
}

void
SimpleRouter::sendPacket(const Buffer& packet, const std::string& outIface)
{
  m_pox->begin_sendPacket(packet, outIface);
}

bool
SimpleRouter::loadRoutingTable(const std::string& rtConfig)
{
  return m_routingTable.load(rtConfig);
}

void
SimpleRouter::loadIfconfig(const std::string& ifconfig)
{
  std::ifstream iff(ifconfig.c_str());
  std::string line;
  while (std::getline(iff, line)) {
    std::istringstream ifLine(line);
    std::string iface, ip;
    ifLine >> iface >> ip;

    in_addr ip_addr;
    if (inet_aton(ip.c_str(), &ip_addr) == 0) {
      throw std::runtime_error("Invalid IP address `" + ip + "` for interface `" + iface + "`");
    }

    m_ifNameToIpMap[iface] = ip_addr.s_addr;
  }
}

void
SimpleRouter::printIfaces(std::ostream& os)
{
  if (m_ifaces.empty()) {
    os << " Interface list empty " << std::endl;
    return;
  }

  for (const auto& iface : m_ifaces) {
    os << iface << "\n";
  }
  os.flush();
}

const Interface*
SimpleRouter::findIfaceByIp(uint32_t ip) const
{
  auto iface = std::find_if(m_ifaces.begin(), m_ifaces.end(), [ip] (const Interface& iface) {
      return iface.ip == ip;
    });

  if (iface == m_ifaces.end()) {
    return nullptr;
  }

  return &*iface;
}

const Interface*
SimpleRouter::findIfaceByMac(const Buffer& mac) const
{
  auto iface = std::find_if(m_ifaces.begin(), m_ifaces.end(), [mac] (const Interface& iface) {
      return iface.addr == mac;
    });

  if (iface == m_ifaces.end()) {
    return nullptr;
  }

  return &*iface;
}

const Interface*
SimpleRouter::findIfaceByName(const std::string& name) const
{
  auto iface = std::find_if(m_ifaces.begin(), m_ifaces.end(), [name] (const Interface& iface) {
      return iface.name == name;
    });

  if (iface == m_ifaces.end()) {
    return nullptr;
  }

  return &*iface;
}

void
SimpleRouter::reset(const pox::Ifaces& ports)
{
  std::cerr << "Resetting SimpleRouter with " << ports.size() << " ports" << std::endl;

  m_arp.clear();
  m_ifaces.clear();

  for (const auto& iface : ports) {
    auto ip = m_ifNameToIpMap.find(iface.name);
    if (ip == m_ifNameToIpMap.end()) {
      std::cerr << "IP_CONFIG missing information about interface `" + iface.name + "`. Skipping it" << std::endl;
      continue;
    }

    m_ifaces.insert(Interface(iface.name, iface.mac, ip->second));
  }

  printIfaces(std::cerr);
}


} // namespace simple_router {
