// SPDX-License-Identifier: MIT
#ifndef CANDY_KERNEL_ROUTE_H
#define CANDY_KERNEL_ROUTE_H

#include "core/net.h"
#include <string>

namespace candy {

/**
 * Add a route to the Linux kernel routing table using netlink.
 * This is more modern and powerful than ioctl.
 *
 * @param dst Destination network address
 * @param mask Network mask
 * @param gateway Next hop gateway address
 * @param dev Output interface name (e.g., "candy", "tun0")
 * @return 0 on success, -1 on failure
 */
int addKernelRoute(uint32_t dst, uint32_t mask, uint32_t gateway, const std::string &dev);

/**
 * Delete a route from the Linux kernel routing table using netlink.
 *
 * @param dst Destination network address
 * @param mask Network mask
 * @param gateway Next hop gateway address
 * @param dev Output interface name
 * @return 0 on success, -1 on failure
 */
int delKernelRoute(uint32_t dst, uint32_t mask, uint32_t gateway, const std::string &dev);

/**
 * Look up the next hop for a destination address using netlink.
 * This queries the kernel's routing table (radix tree) for fast lookup.
 *
 * @param daddr Destination address to look up
 * @param nexthop Output: next hop address (filled only on success)
 * @param iface Output: output interface name (filled only on success)
 * @return 0 on success (nexthop found), -1 on failure (no route)
 */
int lookupKernelRoute(uint32_t daddr, uint32_t &nexthop, std::string &iface);

/**
 * Add a route to the kernel routing table using SysRouteEntry.
 */
inline int addKernelRoute(const SysRouteEntry &entry, const std::string &dev) {
    return addKernelRoute(entry.dst, entry.mask, entry.nexthop, dev);
}

} // namespace candy

#endif
