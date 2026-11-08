package keycheckprobe

import (
	"bytes"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"tross/core/keycheck"
)

func TestWriteConfigIsPrivateAndDoesNotStoreURI(t *testing.T) {
	dir := t.TempDir()
	prober := SingBoxProber{Binary: "sing-box", WorkDir: dir}
	path, err := prober.writeConfig("record-1", keycheck.OutboundSpec{Type: "vless", Server: "edge.example.test", ServerName: "edge.example.test", UUID: "credential", Port: 443, TLS: true}, 18080)
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %v, error = %v", info.Mode().Perm(), err)
	}
	if filepath.Dir(path) != filepath.Join(dir, "runs") {
		t.Fatalf("path = %q", path)
	}
}

func TestWriteConfigUpdatesPrivateRecordConfigForNewPort(t *testing.T) {
	dir := t.TempDir()
	prober := SingBoxProber{Binary: "sing-box", WorkDir: dir}
	spec := keycheck.OutboundSpec{Type: "vless", Server: "edge.example.test", ServerName: "edge.example.test", UUID: "credential", Port: 443, TLS: true}
	first, err := prober.writeConfig("record-1", spec, 18080)
	if err != nil {
		t.Fatal(err)
	}
	second, err := prober.writeConfig("record-1", spec, 18081)
	if err != nil {
		t.Fatal(err)
	}
	if second != first {
		t.Fatalf("config path changed: %q != %q", second, first)
	}
	data, err := os.ReadFile(second)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(data, []byte(`"listen_port":18081`)) {
		t.Fatalf("new port is absent from config: %s", data)
	}
}

func TestValidateTarget(t *testing.T) {
	if validateTarget("https://www.gstatic.com/generate_204") != nil {
		t.Fatal("valid HTTPS target rejected")
	}
	if validateTarget("file:///tmp/test") == nil {
		t.Fatal("non-HTTP target accepted")
	}
}
