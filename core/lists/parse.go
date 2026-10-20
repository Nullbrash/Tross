package lists

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"strings"

	"golang.org/x/net/idna"

	"tross/core/model"
)

// Parsed — правила источника без слоя и назначения (их ставит загрузчик).
// Entry — домен из списка и способ сопоставления.
type Entry struct {
	Pattern string
	Match   model.MatchKind
}

type Parsed struct {
	// Entries — только домены: назначение и класс у источника общие, а
	// полная запись правила на каждый из миллиона доменов — сотни МБ
	// временной памяти при разборе.
	Entries []Entry
	// Skipped — понятные, но неподдерживаемые записи (regexp), Bad — мусор.
	Skipped, Bad int
}

// NormalizeName — имя из списка в вид правила: нижний регистр, без точек по
// краям и «*.»/«+.», IDN — в punycode (в российских списках есть .рф).
func NormalizeName(s string) (string, error) {
	s = strings.TrimSpace(s)
	for _, p := range []string{"*.", "+.", "."} {
		s = strings.TrimPrefix(s, p)
	}
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			a, err := idna.Lookup.ToASCII(s)
			if err != nil {
				return "", err
			}
			s = a
			break
		}
	}
	return model.NormalizeDomain(s)
}

// ParseText — по записи в строке: домен (с поддоменами), `domain:`, `full:`,
// `keyword:` (формат v2fly), строка hosts-файла, `||домен^` (блокировщики
// рекламы). Комментарии — `#`, `!`, `//`; хвост после пробела (атрибуты
// `@ads`) отбрасывается. `regexp:` пропускается.
func ParseText(r io.Reader) (Parsed, error) {
	var p Parsed
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || line[0] == '#' || line[0] == '!' || strings.HasPrefix(line, "//") {
			continue
		}
		f := strings.Fields(line)
		entry := f[0]
		if len(f) >= 2 && (entry == "0.0.0.0" || entry == "127.0.0.1") {
			entry = f[1] // hosts-файл
			if entry == "localhost" || entry == "0.0.0.0" {
				continue
			}
		}
		kind := model.MatchSuffix
		switch {
		case strings.HasPrefix(entry, "||"):
			entry = strings.TrimSuffix(strings.TrimPrefix(entry, "||"), "^")
		case strings.HasPrefix(entry, "full:"):
			entry, kind = entry[5:], model.MatchExact
		case strings.HasPrefix(entry, "domain:"):
			entry = entry[7:]
		case strings.HasPrefix(entry, "keyword:"):
			entry, kind = strings.ToLower(entry[8:]), model.MatchKeyword
		case strings.HasPrefix(entry, "regexp:"):
			p.Skipped++
			continue
		}
		if kind != model.MatchKeyword {
			n, err := NormalizeName(entry)
			if err != nil {
				p.Bad++
				continue
			}
			entry = n
		} else if entry == "" {
			p.Bad++
			continue
		}
		p.Entries = append(p.Entries, Entry{Pattern: entry, Match: kind})
	}
	return p, sc.Err()
}

// ParseGeosite — категории (без учёта регистра) из файла geosite v2fly
// (protobuf GeoSiteList). Категории, которых нет в файле, — ошибка: опечатка
// в конфиге не должна молча давать пустой список.
func ParseGeosite(data []byte, categories []string) (Parsed, error) {
	want := map[string]bool{}
	for _, c := range categories {
		want[strings.ToUpper(c)] = true
	}
	found := map[string]bool{}
	var p Parsed
	err := protoFields(data, func(num int, b []byte) error {
		if num != 1 {
			return nil
		}
		var code string
		var domains [][]byte
		err := protoFields(b, func(num int, v []byte) error {
			switch num {
			case 1:
				code = strings.ToUpper(string(v))
			case 2:
				domains = append(domains, v)
			}
			return nil
		})
		if err != nil || !want[code] {
			return err
		}
		found[code] = true
		for _, d := range domains {
			if err := geositeDomain(d, &p); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		return Parsed{}, err
	}
	var missing []string
	for c := range want {
		if !found[c] {
			missing = append(missing, strings.ToLower(c))
		}
	}
	if len(missing) > 0 {
		return Parsed{}, fmt.Errorf("geosite: no categories %v", missing)
	}
	return p, nil
}

// Тип домена geosite: Plain (подстрока), Regex, RootDomain (с поддоменами), Full.
const (
	geoPlain = iota
	geoRegex
	geoRoot
	geoFull
)

func geositeDomain(b []byte, p *Parsed) error {
	typ, value := uint64(geoPlain), ""
	err := protoFields(b, func(num int, v []byte) error {
		switch num {
		case 1:
			t, _, err := varint(v)
			typ = t
			return err
		case 2:
			value = string(v)
		}
		return nil
	})
	if err != nil {
		return err
	}
	var kind model.MatchKind
	switch typ {
	case geoRoot:
		kind = model.MatchSuffix
	case geoFull:
		kind = model.MatchExact
	case geoPlain:
		kind = model.MatchKeyword
	default:
		p.Skipped++
		return nil
	}
	if kind == model.MatchKeyword {
		value = strings.ToLower(value)
	} else if n, err := NormalizeName(value); err == nil {
		value = n
	} else {
		p.Bad++
		return nil
	}
	if value == "" {
		p.Bad++
		return nil
	}
	p.Entries = append(p.Entries, Entry{Pattern: value, Match: kind})
	return nil
}

var errProto = errors.New("geosite: malformed protobuf")

// protoFields вызывает fn для каждого поля сообщения; для varint-поля v —
// его байты, для length-delimited — содержимое.
func protoFields(b []byte, fn func(num int, v []byte) error) error {
	for len(b) > 0 {
		tag, n, err := varint(b)
		if err != nil {
			return err
		}
		b = b[n:]
		num, wire := int(tag>>3), tag&7
		var v []byte
		switch wire {
		case 0:
			_, n, err := varint(b)
			if err != nil {
				return err
			}
			v, b = b[:n], b[n:]
		case 1, 5:
			size := 8
			if wire == 5 {
				size = 4
			}
			if len(b) < size {
				return errProto
			}
			v, b = b[:size], b[size:]
		case 2:
			l, n, err := varint(b)
			if err != nil || uint64(len(b)-n) < l {
				return errProto
			}
			v, b = b[n:n+int(l)], b[n+int(l):]
		default:
			return errProto
		}
		if err := fn(num, v); err != nil {
			return err
		}
	}
	return nil
}

func varint(b []byte) (uint64, int, error) {
	var x uint64
	for i := 0; i < len(b) && i < 10; i++ {
		x |= uint64(b[i]&0x7f) << (7 * i)
		if b[i] < 0x80 {
			return x, i + 1, nil
		}
	}
	return 0, 0, errProto
}
