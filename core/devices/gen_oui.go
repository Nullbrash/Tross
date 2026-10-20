//go:build ignore

// Сборка oui.txt.gz из реестров IEEE (oui.csv, mam.csv, oui36.csv):
//
//	go run gen_oui.go -dir <каталог с CSV>
//
// Строка — «префикс в hex<TAB>производитель», по возрастанию префикса;
// длина префикса — 6, 7 или 9 знаков (MA-L, MA-M, MA-S).
package main

import (
	"compress/gzip"
	"encoding/csv"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// Правовые формы в конце названия — шум для подсказки в интерфейсе.
var suffix = regexp.MustCompile(`(?i)[\s,.]+(inc|incorporated|corp|corporation|co|company|ltd|limited|llc|l\.l\.c|gmbh|ag|sa|s\.a|s\.a\.s|srl|s\.r\.l|spa|s\.p\.a|bv|b\.v|nv|ab|as|a/s|oy|kg|plc|pte|pty|kk|k\.k|sdn\s+bhd|co\.?,?\s*ltd)\.?$`)

func clean(name string) string {
	name = strings.Join(strings.Fields(name), " ")
	for {
		n := strings.TrimRight(suffix.ReplaceAllString(name, ""), " ,.")
		if n == name || n == "" {
			return name
		}
		name = n
	}
}

func main() {
	dir := flag.String("dir", ".", "directory with oui.csv, mam.csv, oui36.csv")
	out := flag.String("out", "oui.txt.gz", "output file")
	flag.Parse()

	entries := map[string]string{}
	for _, f := range []string{"oui.csv", "mam.csv", "oui36.csv"} {
		fh, err := os.Open(filepath.Join(*dir, f))
		if err != nil {
			log.Fatal(err)
		}
		rows, err := csv.NewReader(fh).ReadAll()
		fh.Close()
		if err != nil {
			log.Fatalf("%s: %v", f, err)
		}
		for _, r := range rows[1:] {
			if len(r) < 3 {
				continue
			}
			prefix, name := strings.ToLower(strings.TrimSpace(r[1])), clean(r[2])
			// Блоки MA-L, поделённые на MA-M/MA-S, и скрытые записи — без
			// производителя.
			if name == "" || strings.EqualFold(name, "IEEE Registration Authority") || strings.EqualFold(name, "Private") {
				continue
			}
			switch len(prefix) {
			case 6, 7, 9:
				entries[prefix] = name
			default:
				log.Fatalf("%s: bad prefix %q", f, r[1])
			}
		}
	}
	keys := make([]string, 0, len(entries))
	for k := range entries {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	fh, err := os.Create(*out)
	if err != nil {
		log.Fatal(err)
	}
	zw, _ := gzip.NewWriterLevel(fh, gzip.BestCompression)
	for _, k := range keys {
		fmt.Fprintf(zw, "%s\t%s\n", k, entries[k])
	}
	if err := zw.Close(); err != nil {
		log.Fatal(err)
	}
	if err := fh.Close(); err != nil {
		log.Fatal(err)
	}
	log.Printf("%d prefixes → %s", len(keys), *out)
}
