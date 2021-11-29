// Copyright 2020 The Prometheus Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//go:build !nonetworkroute
// +build !nonetworkroute

package collector

import (
	"fmt"
	"golang.org/x/sys/unix"
	"net"
	"strconv"

	"github.com/go-kit/log"
	"github.com/vishvananda/netlink"
	"github.com/prometheus/client_golang/prometheus"
)

type networkRouteCollector struct {
	routeInfoDesc *prometheus.Desc
	routesDesc    *prometheus.Desc
	logger        log.Logger
}

func init() {
	registerCollector("network_route", defaultDisabled, NewNetworkRouteCollector)
}

// NewNetworkRouteCollector returns a new Collector exposing systemd statistics.
func NewNetworkRouteCollector(logger log.Logger) (Collector, error) {
	const subsystem = "network"

	routeInfoDesc := prometheus.NewDesc(
		prometheus.BuildFQName(namespace, subsystem, "route_info"),
		"network routing table information", []string{"device", "src", "dest", "gw", "priority", "proto", "weight", "family", "table"}, nil,
	)
	routesDesc := prometheus.NewDesc(
		prometheus.BuildFQName(namespace, subsystem, "routes"),
		"network routes by interface", []string{"device"}, nil,
	)

	return &networkRouteCollector{
		routeInfoDesc: routeInfoDesc,
		routesDesc:    routesDesc,
		logger:        logger,
	}, nil
}

func (n networkRouteCollector) Update(ch chan<- prometheus.Metric) error {
	deviceRoutes := make(map[string]int)

	links, err := netlink.LinkList()
	if err != nil {
		return fmt.Errorf("couldn't get links: %w", err)
	}

	routingTableMaps := networkRouteGenerateRoutingTableMap(links)

	routesByFamily, err := networkRouteGet()
	if err != nil {
		return fmt.Errorf("couldn't get routes: %w", err)
	}

	for family, routes := range routesByFamily {
		for _, route := range routes {
			if route.Type != unix.RTA_DST {
				continue
			}
			if len(route.MultiPath) != 0 {
				for _, nextHop := range route.MultiPath {
					ifName := ""
					for _, link := range links {
						if link.Attrs().Index == nextHop.LinkIndex {
							ifName = link.Attrs().Name
							break
						}
					}

					labels := []string{
						ifName,                                              // if
						networkRouteIPToString(route.Src),                   // src
						networkRouteDestPrefix(route.Dst),                   // dest
						networkRouteIPToString(nextHop.Gw),                  // gw
						strconv.FormatUint(uint64(route.Priority), 10),      // priority(metrics)
						networkRouteProtocolToString(uint8(route.Protocol)), // proto
						strconv.Itoa(int(nextHop.Hops) + 1),                 // weight
						family,                                              // Family
						routingTableMaps[route.Table],                       // Table
					}
					ch <- prometheus.MustNewConstMetric(n.routeInfoDesc, prometheus.GaugeValue, 1, labels...)
					deviceRoutes[ifName]++
				}
			} else {
				ifName := ""
				for _, link := range links {
					if link.Attrs().Index == route.LinkIndex {
						ifName = link.Attrs().Name
						break
					}
				}

				labels := []string{
					ifName,                                              // if
					networkRouteIPToString(route.Src),                   // src
					networkRouteDestPrefix(route.Dst),                   // dest
					networkRouteIPToString(route.Gw),                    // gw
					strconv.FormatUint(uint64(route.Priority), 10),      // priority(metrics)
					networkRouteProtocolToString(uint8(route.Protocol)), // proto
					"",                            // weight
					family,                        // Family
					routingTableMaps[route.Table], // Table
				}
				ch <- prometheus.MustNewConstMetric(n.routeInfoDesc, prometheus.GaugeValue, 1, labels...)
				deviceRoutes[ifName]++
			}
		}
	}
	for dev, total := range deviceRoutes {
		ch <- prometheus.MustNewConstMetric(n.routesDesc, prometheus.GaugeValue, float64(total), dev)
	}

	return nil
}

func networkRouteGet() (map[string][]netlink.Route, error) {
	routeFilter := &netlink.Route{
		Table: 0,
	}

	v4Routes, err := netlink.RouteListFiltered(netlink.FAMILY_V4, routeFilter, netlink.RT_FILTER_TABLE)
	if err != nil {
		return nil, err
	}

	v6Routes, err := netlink.RouteListFiltered(netlink.FAMILY_V6, routeFilter, netlink.RT_FILTER_TABLE)
	if err != nil {
		return nil, err
	}

	routes := map[string][]netlink.Route{
		"IPv4": v4Routes,
		"IPv6": v6Routes,
	}

	return routes, nil
}

func networkRouteIPToString(ip net.IP) string {
	if len(ip) == 0 {
		return ""
	}
	return ip.String()
}

func networkRouteProtocolToString(protocol uint8) string {
	// from linux kernel 'include/uapi/linux/rtnetlink.h'
	switch protocol {
	case 0:
		return "unspec"
	case 1:
		return "redirect"
	case 2:
		return "kernel"
	case 3:
		return "boot"
	case 4:
		return "static"
	case 8:
		return "gated"
	case 9:
		return "ra"
	case 10:
		return "mrt"
	case 11:
		return "zebra"
	case 12:
		return "bird"
	case 13:
		return "dnrouted"
	case 14:
		return "xorp"
	case 15:
		return "ntk"
	case 16:
		return "dhcp"
	case 17:
		return "mrouted"
	case 42:
		return "babel"
	case 186:
		return "bgp"
	case 187:
		return "isis"
	case 188:
		return "ospf"
	case 189:
		return "rip"
	case 192:
		return "eigrp"
	}
	return "unknown"
}

func networkRouteDestPrefix(dst *net.IPNet) string {
	if dst == nil {
		return "default"
	}
	return fmt.Sprintf("%s", dst)
}

func networkRouteGenerateRoutingTableMap(links []netlink.Link) map[int]string {
	rtm := map[int]string{
		253: "default",
		254: "main",
		255: "local",
	}

	for _, link := range links {
		linkType := link.Type()
		if linkType == "vrf" {
			vrf := link.(*netlink.Vrf)
			rtm[int(vrf.Table)] = vrf.Name
		}
	}

	return rtm
}
