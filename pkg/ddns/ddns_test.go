package ddns

import (
	"context"
	"net/netip"
	"testing"

	"github.com/libdns/libdns"
	"github.com/nezhahq/nezha/model"
	"github.com/stretchr/testify/require"
)

type testSt struct {
	domain string
	zone   string
	prefix string
}

func TestSplitDomainSOA(t *testing.T) {
	cases := []testSt{
		{
			domain: "www.example.co.uk",
			zone:   "example.co.uk.",
			prefix: "www",
		},
		{
			domain: "abc.example.com",
			zone:   "example.com.",
			prefix: "abc",
		},
		{
			domain: "example.com",
			zone:   "example.com.",
			prefix: "",
		},
	}

	ctx := context.WithValue(context.Background(), DNSServerKey{}, []string{"1.1.1.1:53"})
	provider := &Provider{}
	for _, c := range cases {
		prefix, zone, err := provider.splitDomainSOA(ctx, c.domain)
		if err != nil {
			t.Fatalf("Error: %s", err)
		}
		if prefix != c.prefix {
			t.Fatalf("Expected prefix %s, but got %s", c.prefix, prefix)
		}
		if zone != c.zone {
			t.Fatalf("Expected zone %s, but got %s", c.zone, zone)
		}
	}
}

type recordingSetter struct {
	records []libdns.Record
}

func (s *recordingSetter) SetRecords(_ context.Context, _ string, records []libdns.Record) ([]libdns.Record, error) {
	s.records = records
	return records, nil
}

func TestProviderSetsMultipleAddressRecords(t *testing.T) {
	enableIPv4 := true
	setter := &recordingSetter{}
	provider := &Provider{
		DDNSProfile: &model.DDNSProfile{
			Provider:   model.ProviderDummy,
			EnableIPv4: &enableIPv4,
			MaxRetries: 1,
		},
		IPRecords: &IPRecords{IPv4Addrs: []string{"1.0.0.1", "1.1.1.1"}},
		Setter:    setter,
	}

	err := provider.updateDomain(context.Background(), "cdn.example.com")
	require.NoError(t, err)
	require.Len(t, setter.records, 2)

	first := setter.records[0].(libdns.Address)
	second := setter.records[1].(libdns.Address)
	require.Equal(t, netip.MustParseAddr("1.0.0.1"), first.IP)
	require.Equal(t, netip.MustParseAddr("1.1.1.1"), second.IP)
}

type recordingRRSetReplacer struct {
	existing []libdns.Record
	deleted  []libdns.Record
	appended []libdns.Record
	set      []libdns.Record
}

func (s *recordingRRSetReplacer) GetRecords(_ context.Context, _ string) ([]libdns.Record, error) {
	return s.existing, nil
}

func (s *recordingRRSetReplacer) DeleteRecords(_ context.Context, _ string, records []libdns.Record) ([]libdns.Record, error) {
	s.deleted = append(s.deleted, records...)
	return records, nil
}

func (s *recordingRRSetReplacer) AppendRecords(_ context.Context, _ string, records []libdns.Record) ([]libdns.Record, error) {
	s.appended = append(s.appended, records...)
	return records, nil
}

func (s *recordingRRSetReplacer) SetRecords(_ context.Context, _ string, records []libdns.Record) ([]libdns.Record, error) {
	s.set = append(s.set, records...)
	return records, nil
}

func TestProviderReplacesAddressRRSetBeforeAppendingMultipleRecords(t *testing.T) {
	replacer := &recordingRRSetReplacer{
		existing: []libdns.Record{
			libdns.Address{Name: "cdn", IP: netip.MustParseAddr("8.8.8.8")},
			libdns.Address{Name: "cdn", IP: netip.MustParseAddr("8.8.4.4")},
			libdns.Address{Name: "other", IP: netip.MustParseAddr("9.9.9.9")},
			libdns.Address{Name: "cdn", IP: netip.MustParseAddr("2001:4860:4860::8888")},
		},
	}
	provider := &Provider{Setter: replacer}
	provider.prefix = "cdn"
	provider.zone = "example.com."

	err := provider.addDomainRecords(context.Background(), "A", []string{"1.0.0.1", "1.1.1.1"})
	require.NoError(t, err)

	require.Empty(t, replacer.set)
	require.Len(t, replacer.deleted, 2)
	require.Len(t, replacer.appended, 2)

	deletedFirst := replacer.deleted[0].(libdns.Address)
	deletedSecond := replacer.deleted[1].(libdns.Address)
	require.Equal(t, netip.MustParseAddr("8.8.8.8"), deletedFirst.IP)
	require.Equal(t, netip.MustParseAddr("8.8.4.4"), deletedSecond.IP)

	appendedFirst := replacer.appended[0].(libdns.Address)
	appendedSecond := replacer.appended[1].(libdns.Address)
	require.Equal(t, netip.MustParseAddr("1.0.0.1"), appendedFirst.IP)
	require.Equal(t, netip.MustParseAddr("1.1.1.1"), appendedSecond.IP)
}
