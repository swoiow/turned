package turned

import (
	"fmt"
	"net"
)

func ParseEDNS0SubNet(clientSubnet string) (net.IP, uint8) {
	ip := net.ParseIP(clientSubnet)
	if ip != nil {
		clientSubnet = fmt.Sprintf("%s/24", ip)
	}

	_, ipNet, err := net.ParseCIDR(clientSubnet)
	if err != nil {
		log.Errorf("unable to parse subnet: %s", clientSubnet)
		return nil, 0
	}
	netMark, _ := ipNet.Mask.Size()
	if netMark >= 32 {
		log.Errorf("%s net mark should less than 32", clientSubnet)
		return nil, 0
	}
	return ipNet.IP, uint8(netMark)
}
