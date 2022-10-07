package turned

import (
	"net"
	"reflect"
	"testing"
)

func TestParseEDNS0SubNet(t *testing.T) {
	type args struct {
		clientSubnet string
	}
	tests := []struct {
		name       string
		args       args
		expectIp   net.IP
		expectMark uint8
	}{
		{name: "example1", args: args{"1.1.1.0"}, expectIp: net.IP("1.1.1.0"), expectMark: 24},
		{name: "example1", args: args{"1.1.1.1"}, expectIp: net.IP("1.1.1.0"), expectMark: 24},
		{name: "example1", args: args{"1.1.1.1/24"}, expectIp: net.IP("1.1.1.0"), expectMark: 24},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip, mark := ParseEDNS0SubNet(tt.args.clientSubnet)
			if !reflect.DeepEqual(ip, tt.expectIp) {
				t.Errorf("ParseEDNS0SubNet() got = %v, want %v", ip, tt.expectIp)
			}
			if mark != tt.expectMark {
				t.Errorf("ParseEDNS0SubNet() got1 = %v, want %v", mark, tt.expectMark)
			}
		})
	}
}
