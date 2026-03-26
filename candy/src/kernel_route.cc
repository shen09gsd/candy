// SPDX-License-Identifier: MIT
#include "candy/kernel_route.h"
#include <arpa/inet.h>
#include <asm/types.h>
#include <cstring>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <net/if.h>
#include <spdlog/spdlog.h>
#include <sys/socket.h>
#include <unistd.h>

namespace candy {

// Netlink route message structure
struct nl_req_t {
    struct nlmsghdr hdr;
    struct rtmsg msg;
    char buf[1024];
};

/**
 * Create a netlink socket for routing operations.
 */
static int createNetlinkSocket() {
    int sock = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    if (sock < 0) {
        spdlog::error("create netlink socket failed: {}", strerror(errno));
        return -1;
    }

    struct sockaddr_nl addr;
    memset(&addr, 0, sizeof(addr));
    addr.nl_family = AF_NETLINK;
    addr.nl_pid = getpid();
    addr.nl_groups = 0;

    if (bind(sock, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        spdlog::error("bind netlink socket failed: {}", strerror(errno));
        close(sock);
        return -1;
    }

    return sock;
}

/**
 * Send a netlink request and receive response.
 */
static int sendNetlinkRequest(int sock, struct nlmsghdr *hdr, struct nlmsghdr **resp, int *resp_len) {
    struct sockaddr_nl addr;
    memset(&addr, 0, sizeof(addr));
    addr.nl_family = AF_NETLINK;

    // Send request
    if (sendto(sock, hdr, hdr->nlmsg_len, 0, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        spdlog::error("send netlink request failed: {}", strerror(errno));
        return -1;
    }

    // Receive response
    char buf[8192];
    int len = recv(sock, buf, sizeof(buf), 0);
    if (len < 0) {
        spdlog::error("recv netlink response failed: {}", strerror(errno));
        return -1;
    }

    *resp = (struct nlmsghdr *)malloc(len);
    if (!*resp) {
        return -1;
    }
    memcpy(*resp, buf, len);
    *resp_len = len;

    return 0;
}

/**
 * Add a route to the kernel routing table using netlink.
 */
int addKernelRoute(uint32_t dst, uint32_t mask, uint32_t gateway, const std::string &dev) {
    int sock = createNetlinkSocket();
    if (sock < 0) {
        return -1;
    }

    struct {
        struct nlmsghdr n;
        struct rtmsg r;
        struct rtattr rta[4];
        char buf[256];
    } req;

    memset(&req, 0, sizeof(req));
    req.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
    req.n.nlmsg_type = RTM_NEWROUTE;
    req.n.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_REPLACE;
    req.n.nlmsg_seq = 1;

    req.r.rtm_family = AF_INET;
    req.r.rtm_dst_len = 0; // Will be set by rta
    req.r.rtm_table = RT_TABLE_MAIN;
    req.r.rtm_protocol = RTPROT_BOOT;
    req.r.rtm_scope = RT_SCOPE_UNIVERSE;
    req.r.rtm_type = RTN_UNICAST;

    // Calculate prefix length from mask
    int prefix_len = 0;
    uint32_t m = mask;
    while (m) {
        prefix_len++;
        m >>= 1;
    }
    req.r.rtm_dst_len = prefix_len;

    // Add destination attribute (RTA_DST)
    req.rta[0].rta_type = RTA_DST;
    req.rta[0].rta_len = RTA_SPACE(sizeof(dst));
    memcpy(RTA_DATA(&req.rta[0]), &dst, sizeof(dst));
    req.n.nlmsg_len += RTA_SPACE(sizeof(dst));

    // Add gateway attribute (RTA_GATEWAY)
    req.rta[1].rta_type = RTA_GATEWAY;
    req.rta[1].rta_len = RTA_SPACE(sizeof(gateway));
    memcpy(RTA_DATA(&req.rta[1]), &gateway, sizeof(gateway));
    req.n.nlmsg_len += RTA_SPACE(sizeof(gateway));

    // Add output interface attribute (RTA_OIF)
    int ifindex = if_nametoindex(dev.c_str());
    if (ifindex == 0) {
        spdlog::error("interface {} not found", dev);
        close(sock);
        return -1;
    }
    req.rta[2].rta_type = RTA_OIF;
    req.rta[2].rta_len = RTA_SPACE(sizeof(ifindex));
    memcpy(RTA_DATA(&req.rta[2]), &ifindex, sizeof(ifindex));
    req.n.nlmsg_len += RTA_SPACE(sizeof(ifindex));

    // Send request
    struct sockaddr_nl addr;
    memset(&addr, 0, sizeof(addr));
    addr.nl_family = AF_NETLINK;

    if (sendto(sock, &req.n, req.n.nlmsg_len, 0, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        spdlog::error("send netlink add route failed: {}", strerror(errno));
        close(sock);
        return -1;
    }

    // Wait for ACK
    char buf[256];
    int len = recv(sock, buf, sizeof(buf), 0);
    close(sock);

    if (len < 0) {
        spdlog::error("recv netlink ack failed: {}", strerror(errno));
        return -1;
    }

    struct nlmsghdr *nh = (struct nlmsghdr *)buf;
    if (nh->nlmsg_type == NLMSG_ERROR) {
        struct nlmsgerr *err = (struct nlmsgerr *)NLMSG_DATA(nh);
        if (err->error != 0) {
            spdlog::error("netlink add route error: {}", strerror(-err->error));
            return -1;
        }
    }

    char dst_str[INET_ADDRSTRLEN], gw_str[INET_ADDRSTRLEN];
    struct in_addr dst_addr = {dst};
    struct in_addr gw_addr = {gateway};
    inet_ntop(AF_INET, &dst_addr, dst_str, sizeof(dst_str));
    inet_ntop(AF_INET, &gw_addr, gw_str, sizeof(gw_str));
    spdlog::debug("added kernel route: {}/{} via {} dev {}", dst_str, prefix_len, gw_str, dev);
    return 0;
}

/**
 * Delete a route from the kernel routing table using netlink.
 */
int delKernelRoute(uint32_t dst, uint32_t mask, uint32_t gateway, const std::string &dev) {
    int sock = createNetlinkSocket();
    if (sock < 0) {
        return -1;
    }

    struct {
        struct nlmsghdr n;
        struct rtmsg r;
        struct rtattr rta[4];
        char buf[256];
    } req;

    memset(&req, 0, sizeof(req));
    req.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
    req.n.nlmsg_type = RTM_DELROUTE;
    req.n.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    req.n.nlmsg_seq = 1;

    req.r.rtm_family = AF_INET;
    req.r.rtm_table = RT_TABLE_MAIN;
    req.r.rtm_protocol = RTPROT_BOOT;
    req.r.rtm_scope = RT_SCOPE_UNIVERSE;
    req.r.rtm_type = RTN_UNICAST;

    int prefix_len = 0;
    uint32_t m = mask;
    while (m) {
        prefix_len++;
        m >>= 1;
    }
    req.r.rtm_dst_len = prefix_len;

    // Destination
    req.rta[0].rta_type = RTA_DST;
    req.rta[0].rta_len = RTA_SPACE(sizeof(dst));
    memcpy(RTA_DATA(&req.rta[0]), &dst, sizeof(dst));
    req.n.nlmsg_len += RTA_SPACE(sizeof(dst));

    // Gateway
    if (gateway != 0) {
        req.rta[1].rta_type = RTA_GATEWAY;
        req.rta[1].rta_len = RTA_SPACE(sizeof(gateway));
        memcpy(RTA_DATA(&req.rta[1]), &gateway, sizeof(gateway));
        req.n.nlmsg_len += RTA_SPACE(sizeof(gateway));
    }

    // Output interface
    int ifindex = if_nametoindex(dev.c_str());
    if (ifindex == 0) {
        spdlog::error("interface {} not found", dev);
        close(sock);
        return -1;
    }
    req.rta[2].rta_type = RTA_OIF;
    req.rta[2].rta_len = RTA_SPACE(sizeof(ifindex));
    memcpy(RTA_DATA(&req.rta[2]), &ifindex, sizeof(ifindex));
    req.n.nlmsg_len += RTA_SPACE(sizeof(ifindex));

    struct sockaddr_nl addr;
    memset(&addr, 0, sizeof(addr));
    addr.nl_family = AF_NETLINK;

    if (sendto(sock, &req.n, req.n.nlmsg_len, 0, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        spdlog::error("send netlink del route failed: {}", strerror(errno));
        close(sock);
        return -1;
    }

    char buf[256];
    int len = recv(sock, buf, sizeof(buf), 0);
    close(sock);

    if (len < 0) {
        spdlog::error("recv netlink ack failed: {}", strerror(errno));
        return -1;
    }

    char dst_str[INET_ADDRSTRLEN], gw_str[INET_ADDRSTRLEN];
    struct in_addr dst_addr = {dst};
    struct in_addr gw_addr = {gateway};
    inet_ntop(AF_INET, &dst_addr, dst_str, sizeof(dst_str));
    inet_ntop(AF_INET, &gw_addr, gw_str, sizeof(gw_str));
    spdlog::debug("deleted kernel route: {}/{} via {}", dst_str, prefix_len, gw_str);
    return 0;
}

/**
 * Look up route using netlink - queries kernel routing table (radix tree).
 * This is O(log n) instead of O(n) linear scan.
 */
int lookupKernelRoute(uint32_t daddr, uint32_t &nexthop, std::string &iface) {
    int sock = createNetlinkSocket();
    if (sock < 0) {
        return -1;
    }

    struct {
        struct nlmsghdr n;
        struct rtmsg r;
        char buf[256];
    } req;

    memset(&req, 0, sizeof(req));
    req.n.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
    req.n.nlmsg_type = RTM_GETROUTE;
    req.n.nlmsg_flags = NLM_F_REQUEST;
    req.n.nlmsg_seq = 1;

    req.r.rtm_family = AF_INET;
    req.r.rtm_dst_len = 32; // Exact match for IP address

    // Add destination attribute
    struct rtattr *rta = (struct rtattr *)req.buf;
    rta->rta_type = RTA_DST;
    rta->rta_len = RTA_SPACE(sizeof(daddr));
    memcpy(RTA_DATA(rta), &daddr, sizeof(daddr));
    req.n.nlmsg_len += RTA_SPACE(sizeof(daddr));

    struct sockaddr_nl addr;
    memset(&addr, 0, sizeof(addr));
    addr.nl_family = AF_NETLINK;

    if (sendto(sock, &req.n, req.n.nlmsg_len, 0, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        spdlog::error("send netlink route lookup failed: {}", strerror(errno));
        close(sock);
        return -1;
    }

    // Receive response
    char resp_buf[8192];
    int resp_len = recv(sock, resp_buf, sizeof(resp_buf), 0);
    close(sock);

    if (resp_len < 0) {
        spdlog::error("recv netlink response failed: {}", strerror(errno));
        return -1;
    }

    // Parse response
    struct nlmsghdr *nh = (struct nlmsghdr *)resp_buf;
    for (; NLMSG_OK(nh, resp_len); nh = NLMSG_NEXT(nh, resp_len)) {
        if (nh->nlmsg_type == NLMSG_DONE) {
            break;
        }

        if (nh->nlmsg_type == RTM_NEWROUTE) {
            struct rtmsg *rtm = (struct rtmsg *)NLMSG_DATA(nh);
            struct rtattr *rt_attr = (struct rtattr *)RTM_RTA(rtm);
            int rtl = RTM_PAYLOAD(nh);

            bool found_gateway = false;
            bool found_oif = false;
            uint32_t gateway = 0;
            int ifindex = 0;

            for (; RTA_OK(rt_attr, rtl); rt_attr = RTA_NEXT(rt_attr, rtl)) {
                switch (rt_attr->rta_type) {
                case RTA_GATEWAY:
                    gateway = *(uint32_t *)RTA_DATA(rt_attr);
                    found_gateway = true;
                    break;
                case RTA_OIF:
                    ifindex = *(int *)RTA_DATA(rt_attr);
                    found_oif = true;
                    break;
                }
            }

            if (found_gateway) {
                nexthop = gateway;
                char ifname[IF_NAMESIZE];
                if (if_indextoname(ifindex, ifname)) {
                    iface = ifname;
                }
                return 0;
            }

            if (found_oif) {
                // Local route (directly connected)
                nexthop = daddr; // Nexthop is the destination itself
                char ifname[IF_NAMESIZE];
                if (if_indextoname(ifindex, ifname)) {
                    iface = ifname;
                }
                return 0;
            }
        }
    }

    return -1; // No route found
}

} // namespace candy
