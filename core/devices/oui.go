package devices

import (
	"bufio"
	"bytes"
	"compress/gzip"
	_ "embed"
	"sort"
	"strconv"
	"strings"
	"sync"

	"tross/core/model"
)

//go:generate ../../scripts/oui-update

// Встроенный реестр IEEE (scripts/oui-update): около 54 тыс. префиксов.
//
//go:embed oui.txt.gz
var ouiGz []byte

type ouiEntry struct {
	prefix uint64 // старшие bits бит MAC
	bits   uint8  // 24, 28 или 36
	name   string
}

var (
	ouiOnce sync.Once
	ouiList []ouiEntry // по (bits, prefix)
)

// Распаковка — при первом поиске: демону без устройств база не нужна.
func loadOUI() {
	zr, err := gzip.NewReader(bytes.NewReader(ouiGz))
	if err != nil {
		panic("devices: oui.txt.gz: " + err.Error())
	}
	sc := bufio.NewScanner(zr)
	for sc.Scan() {
		line := sc.Text()
		tab := strings.IndexByte(line, '\t')
		if tab < 0 {
			continue
		}
		p, err := strconv.ParseUint(line[:tab], 16, 64)
		if err != nil {
			continue
		}
		ouiList = append(ouiList, ouiEntry{prefix: p, bits: uint8(tab * 4), name: line[tab+1:]})
	}
	sort.Slice(ouiList, func(i, j int) bool {
		a, b := ouiList[i], ouiList[j]
		if a.bits != b.bits {
			return a.bits < b.bits
		}
		return a.prefix < b.prefix
	})
}

// Vendor — производитель по префиксу MAC (самый длинный из найденных); у
// случайных MAC — пусто: префикс у них ничего не значит.
func Vendor(m model.MAC) string {
	if m.IsRandomized() || m.IsMulticast() || m.IsZero() {
		return ""
	}
	ouiOnce.Do(loadOUI)
	var v uint64
	for _, b := range m {
		v = v<<8 | uint64(b)
	}
	for _, bits := range []uint8{36, 28, 24} {
		p := v >> (48 - uint(bits))
		i := sort.Search(len(ouiList), func(i int) bool {
			e := ouiList[i]
			return e.bits > bits || e.bits == bits && e.prefix >= p
		})
		if i < len(ouiList) && ouiList[i].bits == bits && ouiList[i].prefix == p {
			return ouiList[i].name
		}
	}
	return ""
}
