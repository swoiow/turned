package turned

import (
	"testing"

	"github.com/bits-and-blooms/bloom/v3"
	"github.com/swoiow/dns_utils/loader"
	"github.com/swoiow/dns_utils/parsers"
)

func getFwFrom() *Forward {
	fw := New()
	adapter := NewAdapter()
	lines := []string{"exist.example.com", "example.com"}

	for _, line := range parsers.LooseParser(lines, parsers.DomainParser, 1) {
		adapter.mapAddString(line)
	}
	adapter.setupContainsFunc()

	fw.bottle = adapter
	fw.from = ""

	return fw
}

func getFwRules() *Forward {
	fw := New()
	if fw.bottle == nil {
		bottle := bloom.NewWithEstimates(50_000, 0.001)

		adapter := NewAdapter()
		adapter.BloomFilter = bottle
		adapter.setupContainsFunc()

		fw.bottle = adapter
	}

	m := loader.DetectMethods("https://github.com/swoiow/blocked/raw/conf/dat/apple.txt")
	rules, err := m.LoadRules(false)
	if err != nil {
		panic(err)
	}
	addLines2filter(rules, fw.bottle.BloomFilter)
	fw.from = ""

	return fw
}

func TestForward_match(t *testing.T) {
	fwFrom := getFwFrom()
	fwRules := getFwRules()

	type args struct {
		f *Forward
		d string
	}
	tests := []struct {
		name string
		args args
		want bool
	}{
		{"fw_from", args{fwFrom, "exist.example.com"}, true},
		{"fw_from", args{fwFrom, "not-exist.example.com"}, false},

		{"fw_rules", args{fwRules, "xp.apple.com"}, true},
		{"fw_rules", args{fwRules, "xp.apple.com.akadns.net"}, true},
		{"fw_rules", args{fwRules, "*.icloud.com"}, true},

		{"fw_rules", args{fwRules, "ipcdn.apple.com.akadns.net"}, true},
		{"fw_rules", args{fwRules, "gs-loc-cn.apple.com.akadns.net"}, true},
		{"fw_rules", args{fwRules, "ipcdn.apple.com"}, false},
		{"fw_rules", args{fwRules, "gs-loc-cn.apple.com"}, false},

		{"fw_rules", args{fwRules, "github.com"}, false},
		{"fw_rules", args{fwRules, "fake.cn-apple.com"}, false},
		{"fw_rules", args{fwRules, "# https://support.apple.com/en-us/HT210060"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name+"@"+tt.args.d, func(t *testing.T) {
			if got := tt.args.f.match(tt.args.d); got != tt.want {
				t.Errorf("match() = %v, want %v", got, tt.want)
			}
		})
	}
}
