// SPDX-License-Identifier: MIT
#include "tun/tun.h"
#include "core/client.h"
#include "core/message.h"
#include "core/net.h"
#include <mutex>
#include <shared_mutex>
#include <spdlog/fmt/bin_to_hex.h>

namespace candy {

int Tun::run(Client *client) {
    this->client = client;
    this->msgThread = std::thread([&] {
        spdlog::debug("start thread: tun msg");
        while (getClient().isRunning()) {
            if (handleTunQueue()) {
                break;
            }
        }
        getClient().shutdown();
        spdlog::debug("stop thread: tun msg");
    });
    return 0;
}

int Tun::wait() {
    if (this->tunThread.joinable()) {
        this->tunThread.join();
    }
    if (this->msgThread.joinable()) {
        this->msgThread.join();
    }
    {
        std::unique_lock lock(this->sysRtMutex);
        this->sysRtTable.clear();
    }
    return 0;
}

int Tun::handleTunDevice() {
    std::string buffer;
    int error = read(buffer);
    if (error <= 0) {
        return 0;
    }
    if (buffer.length() < sizeof(IP4Header)) {
        return 0;
    }
    IP4Header *header = (IP4Header *)buffer.data();
    if (!header->isIPv4()) {
        return 0;
    }

    // Use kernel routing via netlink (radix tree O(log n) lookup instead of O(n) linear scan)
    IP4 nextHop;
    std::string iface;
    bool routeFound = lookupRoute(header->daddr, nextHop, iface);

    if (routeFound && !nextHop.empty()) {
        // Check if this is a peer route (nexthop != own IP and nexthop != destination)
        if (nextHop != getIP() && nextHop != header->daddr) {
            // Peer route: need to encapsulate and send to peer
            buffer.insert(0, sizeof(IP4Header), 0);
            header = (IP4Header *)buffer.data();
            header->protocol = 0x04;  // IP-in-IP
            header->saddr = getIP();
            header->daddr = nextHop;
            // Send to peer via peer connection
            this->client->getPeerMsgQueue().write(Msg(MsgKind::PACKET, std::move(buffer)));
            return 0;
        }
    }

    // Local delivery: destination is own IP or directly connected subnet
    if (header->daddr == getIP()) {
        write(buffer);
        return 0;
    }

    // If route found and points to a directly connected interface, write to TUN
    // The kernel has already done the routing decision, we just write to TUN
    if (routeFound && !iface.empty()) {
        // Check if this should be delivered locally (not to a peer)
        bool isPeerRoute = [&]() {
            std::lock_guard lock(this->peerMutex);
            for (auto const &p : peerSubnets) {
                if ((header->daddr & p.first) == p.first) {
                    return true;
                }
            }
            return false;
        }();

        if (!isPeerRoute) {
            // Write to TUN for kernel to deliver locally
            write(buffer);
            return 0;
        }
    }

    // Fallback: send to peer for server to handle routing
    this->client->getPeerMsgQueue().write(Msg(MsgKind::PACKET, std::move(buffer)));
    return 0;
}

int Tun::handleTunQueue() {
    Msg msg = this->client->getTunMsgQueue().read();
    switch (msg.kind) {
    case MsgKind::TIMEOUT:
        break;
    case MsgKind::PACKET:
        handlePacket(std::move(msg));
        break;
    case MsgKind::TUNADDR:
        if (handleTunAddr(std::move(msg))) {
            return -1;
        }
        break;
    case MsgKind::SYSRT:
        handleSysRt(std::move(msg));
        break;
    default:
        spdlog::warn("unexcepted tun message type: {}", static_cast<int>(msg.kind));
        break;
    }
    return 0;
}

int Tun::handlePacket(Msg msg) {
    if (msg.data.size() < sizeof(IP4Header)) {
        spdlog::warn("invalid IPv4 packet: {:n}", spdlog::to_hex(msg.data));
        return 0;
    }
    IP4Header *header = (IP4Header *)msg.data.data();
    if (header->isIPIP()) {
        msg.data.erase(0, sizeof(IP4Header));
        header = (IP4Header *)msg.data.data();
    }
    write(msg.data);
    return 0;
}

int Tun::handleTunAddr(Msg msg) {
    if (setAddress(msg.data)) {
        return -1;
    }

    if (up()) {
        spdlog::critical("tun up failed");
        return -1;
    }

    this->tunThread = std::thread([&] {
        spdlog::debug("start thread: tun");
        while (getClient().isRunning()) {
            if (handleTunDevice()) {
                break;
            }
        }
        getClient().shutdown();
        spdlog::debug("stop thread: tun");

        if (down()) {
            spdlog::critical("tun down failed");
            return;
        }
    });

    return 0;
}

int Tun::handleSysRt(Msg msg) {
    SysRouteEntry *rt = (SysRouteEntry *)msg.data.data();
    if (rt->nexthop != getIP()) {
        spdlog::info("route: {}/{} via {}", rt->dst.toString(), rt->mask.toPrefix(), rt->nexthop.toString());

        // Track peer subnets for encapsulation decisions
        {
            std::lock_guard lock(this->peerMutex);
            peerSubnets[rt->mask] = rt->nexthop;
        }

        if (setSysRtTable(*rt)) {
            return -1;
        }
    }
    return 0;
}

int Tun::setSysRtTable(const SysRouteEntry &entry) {
    std::unique_lock lock(this->sysRtMutex);
    this->sysRtTable.push_back(entry);
    return setSysRtTable(entry.dst, entry.mask, entry.nexthop);
}

bool Tun::lookupRoute(IP4 daddr, IP4 &nexthop, std::string &iface) {
    uint32_t daddr_raw = daddr;
    uint32_t nexthop_raw;
    std::string iface_out;

    // Use netlink to lookup route in kernel routing table (radix tree)
    // This is O(log n) instead of O(n) linear scan
    int ret = candy::lookupKernelRoute(daddr_raw, nexthop_raw, iface_out);

    if (ret == 0) {
        nexthop = nexthop_raw;
        iface = iface_out;
        return true;
    }

    // Fallback to user-space table if netlink lookup fails
    std::shared_lock lock(this->sysRtMutex);
    for (auto const &rt : sysRtTable) {
        if ((daddr_raw & rt.mask) == rt.dst) {
            nexthop = rt.nexthop;
            iface = "";
            return true;
        }
    }

    return false;
}

Client &Tun::getClient() {
    return *this->client;
}

} // namespace candy
