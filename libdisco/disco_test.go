package libdisco

import (
	"bytes"
	"fmt"
	"io"
	"math"
	"net"
	"testing"
	"time"
)

/*
 * These benchmarks were stolen from crypto/tls
 *
 */

func newLocalListener(t testing.TB) net.Listener {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		ln, err = net.Listen("tcp6", "[::1]:0")
	}
	if err != nil {
		t.Fatal(err)
	}
	return ln
}

func throughput(b *testing.B, totalBytes int64) {

	serverKeyPair := GenerateKeypair(nil)

	ln := newLocalListener(b)
	defer ln.Close()

	N := b.N

	// Less than 64KB because Windows appears to use a TCP rwin < 64KB.
	// See Issue #15899.
	const bufsize = 32 << 10

	go func() {
		buf := make([]byte, bufsize)
		for i := 0; i < N; i++ {
			sconn, err := ln.Accept()
			if err != nil {
				// panic rather than synchronize to avoid benchmark overhead
				// (cannot call b.Fatal in goroutine)
				panic(fmt.Errorf("accept: %v", err))
			}
			serverConfig := &Config{
				HandshakePattern: NoiseNK,
				KeyPair:          serverKeyPair,
			}
			srv := Server(sconn, serverConfig)
			if err := srv.Handshake(); err != nil {
				panic(fmt.Errorf("handshake: %v", err))
			}
			if _, err := io.CopyBuffer(srv, srv, buf); err != nil {
				panic(fmt.Errorf("copy buffer: %v", err))
			}
		}
	}()

	b.SetBytes(totalBytes)
	clientConfig := &Config{
		HandshakePattern: NoiseNK,
		RemoteKey:        serverKeyPair.PublicKey[:],
	}

	buf := make([]byte, bufsize)
	chunks := int(math.Ceil(float64(totalBytes) / float64(len(buf))))
	for i := 0; i < N; i++ {
		conn, err := Dial("tcp", ln.Addr().String(), clientConfig)
		if err != nil {
			b.Fatal(err)
		}
		for j := 0; j < chunks; j++ {
			_, err := conn.Write(buf)
			if err != nil {
				b.Fatal(err)
			}
			_, err = io.ReadFull(conn, buf)
			if err != nil {
				b.Fatal(err)
			}
		}
		conn.Close()
	}
}

func BenchmarkThroughput(b *testing.B) {
	for size := 1; size <= 64; size <<= 1 {
		name := fmt.Sprintf("Packet/%dMB", size)
		b.Run(name, func(b *testing.B) {
			throughput(b, int64(size<<20))
		})
	}
}

type slowConn struct {
	net.Conn
	bps int
}

func (c *slowConn) Write(p []byte) (int, error) {
	if c.bps == 0 {
		panic("too slow")
	}
	t0 := time.Now()
	wrote := 0
	for wrote < len(p) {
		time.Sleep(100 * time.Microsecond)
		allowed := int(time.Since(t0).Seconds()*float64(c.bps)) / 8
		if allowed > len(p) {
			allowed = len(p)
		}
		if wrote < allowed {
			n, err := c.Conn.Write(p[wrote:allowed])
			wrote += n
			if err != nil {
				return wrote, err
			}
		}
	}
	return len(p), nil
}

func latency(b *testing.B, bps int) {
	ln := newLocalListener(b)
	defer ln.Close()

	N := b.N

	serverKeyPair := GenerateKeypair(nil)

	go func() {
		for i := 0; i < N; i++ {
			sconn, err := ln.Accept()
			if err != nil {
				// panic rather than synchronize to avoid benchmark overhead
				// (cannot call b.Fatal in goroutine)
				panic(fmt.Errorf("accept: %v", err))
			}
			serverConfig := &Config{
				HandshakePattern: NoiseNK,
				KeyPair:          serverKeyPair,
			}
			srv := Server(&slowConn{sconn, bps}, serverConfig)
			if err := srv.Handshake(); err != nil {
				panic(fmt.Errorf("handshake: %v", err))
			}
			io.Copy(srv, srv)
		}
	}()

	clientConfig := &Config{
		HandshakePattern: NoiseNK,
		RemoteKey:        serverKeyPair.PublicKey[:],
	}

	buf := make([]byte, 16384)
	peek := make([]byte, 1)

	for i := 0; i < N; i++ {
		conn, err := Dial("tcp", ln.Addr().String(), clientConfig)
		if err != nil {
			b.Fatal(err)
		}
		// make sure we're connected and previous connection has stopped
		if _, err := conn.Write(buf[:1]); err != nil {
			b.Fatal(err)
		}
		if _, err := io.ReadFull(conn, peek); err != nil {
			b.Fatal(err)
		}
		if _, err := conn.Write(buf); err != nil {
			b.Fatal(err)
		}
		if _, err = io.ReadFull(conn, peek); err != nil {
			b.Fatal(err)
		}
		conn.Close()
	}
}

func BenchmarkLatency(b *testing.B) {
	for _, kbps := range []int{200, 500, 1000, 2000, 5000} {
		name := fmt.Sprintf("%dkbps", kbps)
		b.Run(name, func(b *testing.B) {
			latency(b, kbps*1000)
		})
	}
}

func TestSerialize(t *testing.T) {
	// init
	s := GenerateKeypair(nil)
	rs := GenerateKeypair(nil)
	hs := Initialize(NoiseIK, true, nil, s, nil, rs, nil)
	// write first message
	var msg []byte
	hs.WriteMessage(nil, &msg)
	// serialize
	serialized := hs.Serialize()
	// unserialize
	hs2 := RecoverState(serialized, nil, s)

	// let's write a message to parse
	hsBob := Initialize(NoiseIK, false, nil, rs, nil, s, nil)
	var msg2 []byte
	hsBob.ReadMessage(msg, &msg2)
	msg2 = msg2[:0]
	hsBob.WriteMessage([]byte("hello"), &msg2)

	// let's parse it
	var msgRcv1, msgRcv2 []byte
	c1, c2, _ := hs.ReadMessage(msg2, &msgRcv1)
	t1, t2, _ := hs2.ReadMessage(msg2, &msgRcv2)

	if !bytes.Equal(msgRcv1, msgRcv2) {
		t.Fatal("received message not as expected")
	}

	if !bytes.Equal(c1.Serialize(), t1.Serialize()) {
		t.Fatal("obtained strobeState not matching")
	}

	if !bytes.Equal(c2.Serialize(), t2.Serialize()) {
		t.Fatal("obtained strobeState not matching")
	}

}
