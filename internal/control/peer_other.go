//go:build !linux

package control

import "net"

// peerIsRoot — вне Linux демон работает только в «сухом» режиме: проверять
// некого, защищает лишь доступ к файлу сокета.
func peerIsRoot(net.Conn) error { return nil }
