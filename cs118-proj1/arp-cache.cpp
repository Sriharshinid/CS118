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

#include "arp-cache.hpp"
#include "core/utils.hpp"
#include "core/interface.hpp"
#include "simple-router.hpp"

#include <algorithm>
#include <iostream>

namespace simple_router {

//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////
// IMPLEMENT THIS METHOD
void
ArpCache::periodicCheckArpRequestsAndCacheEntries()
{
  // for each request in queued requests: handleRequest(request)
  std::list<std::shared_ptr<ArpRequest>>:: iterator reqIt = m_arpRequests.begin();
  while(reqIt != m_arpRequests.end()) {
    if((*reqIt)->nTimesSent < 5) {
      //send another ARP request
      Buffer newARP(sizeof(ethernet_hdr) + sizeof(arp_hdr));

      ethernet_hdr* newPacketEth = (ethernet_hdr*)((uint8_t*)newARP.data());
      arp_hdr* newPacketArp = (arp_hdr*)((uint8_t*)newARP.data() + sizeof(ethernet_hdr));
      const Interface* iface = m_router.findIfaceByName((*reqIt)->packets.front().iface);

      memcpy(newPacketEth->ether_dhost, BroadcastEtherAddr, ETHER_ADDR_LEN);
      memcpy(newPacketEth->ether_shost, iface->addr.data(), ETHER_ADDR_LEN);
      newPacketEth->ether_type = htons(ethertype_arp);


      newPacketArp->arp_hrd = htons(arp_hrd_ethernet);
      newPacketArp->arp_pro = htons(ethertype_ip);
      newPacketArp->arp_op = htons(arp_op_request);
      newPacketArp->arp_hln = 0x06;
      newPacketArp->arp_pln = 0x04;

      memcpy(newPacketArp->arp_sha, iface->addr.data(), ETHER_ADDR_LEN);
      memcpy(newPacketArp->arp_tha, BroadcastEtherAddr, ETHER_ADDR_LEN);

      newPacketArp->arp_sip = iface->ip;
      newPacketArp->arp_tip = (*reqIt)->ip;

      m_router.sendPacket(newARP, iface->name);
      (*reqIt)->timeSent = steady_clock::now();
      (*reqIt)->nTimesSent = (*reqIt)->nTimesSent + 1;
      ++reqIt;
    } else {
      //delete ArpRequest and all pending packets
      reqIt = m_arpRequests.erase(reqIt);
    }
  }



  // remove all entries marked for remove
  std::vector<std::list<std::shared_ptr<ArpEntry>>::iterator> forRemoval;
  std::list<std::shared_ptr<ArpEntry>>::iterator cacheIt = m_cacheEntries.begin();
  while(cacheIt != m_cacheEntries.end()) {
    if(!((*cacheIt)->isValid)) {
      forRemoval.push_back(cacheIt);
    }
    ++cacheIt;
  }

  for(int i = forRemoval.size() -1; i > -1; i--) {
    m_cacheEntries.erase(forRemoval[i]);
  }
}
//////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////

// You should not need to touch the rest of this code.

ArpCache::ArpCache(SimpleRouter& router)
  : m_router(router)
  , m_shouldStop(false)
  , m_tickerThread(std::bind(&ArpCache::ticker, this))
{
}

ArpCache::~ArpCache()
{
  m_shouldStop = true;
  m_tickerThread.join();
}

std::shared_ptr<ArpEntry>
ArpCache::lookup(uint32_t ip)
{
  std::lock_guard<std::mutex> lock(m_mutex);

  for (const auto& entry : m_cacheEntries) {
    if (entry->isValid && entry->ip == ip) {
      return entry;
    }
  }

  return nullptr;
}

std::shared_ptr<ArpRequest>
ArpCache::queueRequest(uint32_t ip, const Buffer& packet, const std::string& iface)
{
  std::lock_guard<std::mutex> lock(m_mutex);

  auto request = std::find_if(m_arpRequests.begin(), m_arpRequests.end(),
                           [ip] (const std::shared_ptr<ArpRequest>& request) {
                             return (request->ip == ip);
                           });

  if (request == m_arpRequests.end()) {
    request = m_arpRequests.insert(m_arpRequests.end(), std::make_shared<ArpRequest>(ip));
  }

  // Add the packet to the list of packets for this request
  (*request)->packets.push_back({packet, iface});
  return *request;
}

void
ArpCache::removeRequest(const std::shared_ptr<ArpRequest>& entry)
{
  std::lock_guard<std::mutex> lock(m_mutex);
  m_arpRequests.remove(entry);
}

std::shared_ptr<ArpRequest>
ArpCache::insertArpEntry(const Buffer& mac, uint32_t ip)
{
  std::lock_guard<std::mutex> lock(m_mutex);

  auto entry = std::make_shared<ArpEntry>();
  entry->mac = mac;
  entry->ip = ip;
  entry->timeAdded = steady_clock::now();
  entry->isValid = true;
  m_cacheEntries.push_back(entry);

  auto request = std::find_if(m_arpRequests.begin(), m_arpRequests.end(),
                           [ip] (const std::shared_ptr<ArpRequest>& request) {
                             return (request->ip == ip);
                           });
  if (request != m_arpRequests.end()) {
    return *request;
  }
  else {
    return nullptr;
  }
}

void
ArpCache::clear()
{
  std::lock_guard<std::mutex> lock(m_mutex);

  m_cacheEntries.clear();
  m_arpRequests.clear();
}

void
ArpCache::ticker()
{
  while (!m_shouldStop) {
    std::this_thread::sleep_for(std::chrono::seconds(1));

    {
      std::lock_guard<std::mutex> lock(m_mutex);

      auto now = steady_clock::now();

      for (auto& entry : m_cacheEntries) {
        if (entry->isValid && (now - entry->timeAdded > SR_ARPCACHE_TO)) {
          entry->isValid = false;
        }
      }

      periodicCheckArpRequestsAndCacheEntries();
    }
  }
}

std::ostream&
operator<<(std::ostream& os, const ArpCache& cache)
{
  std::lock_guard<std::mutex> lock(cache.m_mutex);

  os << "\nMAC            IP         AGE                       VALID\n"
     << "-----------------------------------------------------------\n";

  auto now = steady_clock::now();
  for (const auto& entry : cache.m_cacheEntries) {

    os << macToString(entry->mac) << "   "
       << ipToString(entry->ip) << "   "
       << std::chrono::duration_cast<seconds>((now - entry->timeAdded)).count() << " seconds   "
       << entry->isValid
       << "\n";
  }
  os << std::endl;
  return os;
}

} // namespace simple_router
