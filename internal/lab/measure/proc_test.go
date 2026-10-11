package measure

import "testing"

func TestParseIPLinkJSON(t *testing.T) {
	js := `[{"ifindex":1,"ifname":"lo","stats64":{"rx":{"bytes":10},"tx":{"bytes":10}}},
	{"ifindex":2,"ifname":"wan1","stats64":{"rx":{"bytes":1000,"packets":3},"tx":{"bytes":2000}}}]`
	got, err := ParseIPLinkJSON([]byte(js))
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Name != "wan1" || got[0].RxBytes != 1000 || got[0].TxBytes != 2000 {
		t.Fatalf("links = %+v", got)
	}
}
