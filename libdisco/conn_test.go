package libdisco

import (
	"bytes"
	"fmt"
	"io"
	"strings"
	"testing"
)

// TODO: add more tests from tls/conn_test.go

func verifier([]byte, []byte) bool { return true }

func TestSeveralWriteRead(t *testing.T) {
	// init
	clientConfig := Config{
		KeyPair:              GenerateKeypair(nil),
		HandshakePattern:     Noise_XX,
		StaticPublicKeyProof: []byte{},
		PublicKeyVerifier:    verifier,
	}
	serverConfig := Config{
		KeyPair:              GenerateKeypair(nil),
		HandshakePattern:     Noise_XX,
		StaticPublicKeyProof: []byte{},
		PublicKeyVerifier:    verifier,
	}

	// get a libdisco.listener
	listener, err := Listen("tcp", "127.0.0.1:0", &serverConfig) // port 0 will find out a free port
	if err != nil {
		t.Fatal("cannot setup a listener on localhost:", err)
	}
	defer listener.Close()
	addr := listener.Addr().String()

	// run the server and Accept one connection
	go func(t *testing.T) {
		serverSocket, err2 := listener.Accept()
		if err2 != nil {
			t.Fatal("a server cannot accept()")
		}

		var buf [100]byte

		for {
			n, err2 := serverSocket.Read(buf[:])
			if err2 != nil {
				if err2 == io.EOF {
					return
				}
				t.Fatal("server can't read on socket")
			}
			if !bytes.Equal(buf[:n-1], []byte("hello ")) {
				t.Fatal("received message not as expected")
			}

			//fmt.Println("server received:", string(buf[:n]))
		}

	}(t)

	// Run the client
	clientSocket, err := Dial("tcp", addr, &clientConfig)
	if err != nil {
		t.Fatal("client can't connect to server")
	}

	for i := 0; i < 100; i++ {
		message := "hello " + string(i)
		_, err = clientSocket.Write([]byte(message))
		if err != nil {
			t.Fatal("client can't write on socket")
		}
	}

	clientSocket.Close()

}

func TestHalfDuplex(t *testing.T) {
	// init
	clientConfig := Config{
		KeyPair:              GenerateKeypair(nil),
		HandshakePattern:     Noise_XX,
		StaticPublicKeyProof: []byte{},
		PublicKeyVerifier:    verifier,
		HalfDuplex:           true,
	}
	serverConfig := Config{
		KeyPair:              GenerateKeypair(nil),
		HandshakePattern:     Noise_XX,
		StaticPublicKeyProof: []byte{},
		PublicKeyVerifier:    verifier,
		HalfDuplex:           true,
	}

	// get a libdisco.listener
	listener, err := Listen("tcp", "127.0.0.1:0", &serverConfig)

	if err != nil {
		t.Fatal("cannot setup a listener on localhost:", err)
	}
	addr := listener.Addr().String()

	// run the server and Accept one connection
	go func() {
		serverSocket, err2 := listener.Accept()
		if err2 != nil {
			t.Fatal("a server cannot accept()")
		}

		var buf [10]byte

		for {
			// read message first
			n, err2 := serverSocket.Read(buf[:])
			if err2 != nil {
				if err2 == io.EOF {
					return
				}
				t.Fatal("server can't read on socket")
			}
			if n != 6 {
				t.Fatal("server is supposed to read 6 bytes")
			}
			if !bytes.Equal(buf[:n-1], []byte("hello")) {
				t.Fatal("server received message which is not hello+i")
			}
			// then write message
			_, err = serverSocket.Write(buf[:n])
			if err != nil {
				fmt.Println("ERRROR", err) // debug
				t.Fatal("server can't write on socket")
			}
			if n != 6 {
				t.Fatal("server is supposed to write 6 bytes")
			}
		}

	}()

	// Run the client
	clientSocket, err := Dial("tcp", addr, &clientConfig)

	if err != nil {
		t.Fatal("client can't connect to server")
	}

	var buf [10]byte

	for i := 0; i < 100; i++ {
		// first write `hello + i`
		message := append([]byte("hello"), byte(i))
		n, err := clientSocket.Write(message)
		if err != nil {
			fmt.Println("ERRROR", err) // debug
			t.Fatal("client can't write on socket")
		}
		if n != 6 {
			t.Fatal("client is supposed to write 6 bytes")
		}
		// then read `hello + (i+1)`
		n, err2 := clientSocket.Read(buf[:])
		if err2 != nil {
			t.Fatal("server can't read on socket")
		}
		if n != 6 {
			t.Fatal("server is supposed to read 6 bytes")
		}
		if !bytes.Equal(buf[:n], message) {
			t.Fatal("received message not as expected")
		}
	}

	//
	clientSocket.Close()
	listener.Close()
}

func TestRemotePublicKey(t *testing.T) {
	// init
	clientConfig := Config{
		KeyPair:              GenerateKeypair(nil),
		HandshakePattern:     Noise_XX,
		StaticPublicKeyProof: []byte{},
		PublicKeyVerifier:    verifier,
	}
	serverConfig := Config{
		KeyPair:                        GenerateKeypair(nil),
		HandshakePattern:               Noise_XX,
		StaticPublicKeyProof:           []byte{},
		PublicKeyVerifier:              verifier,
		RemoteAddrContainsRemotePubkey: true,
	}

	// get a libdisco.listener
	listener, err := Listen("tcp", "127.0.0.1:0", &serverConfig) // port 0 will find out a free port
	if err != nil {
		t.Fatal("cannot setup a listener on localhost:", err)
	}
	defer listener.Close()
	addr := listener.Addr().String()

	// run the server and Accept one connection
	go func(t *testing.T) {
		serverSocket, err2 := listener.Accept()
		if err2 != nil {
			t.Fatal("a server cannot accept()")
		}

		var buf [100]byte

		n, err2 := serverSocket.Read(buf[:])
		if err2 != nil {
			if err2 == io.EOF {
				return
			}
			t.Fatal("server can't read on socket")
		}
		// check if the RemoteAddr returns ip:port:pubkey (which is the msg being sent)
		a := strings.Split(serverSocket.RemoteAddr().String(), ":")
		if a[2] != string(buf[:n]) {
			t.Fatal("received message not as expected")
		}
	}(t)

	// Run the client
	clientSocket, err := Dial("tcp", addr, &clientConfig)
	if err != nil {
		t.Fatal("client can't connect to server")
	}

	// need to send a message for the handshake to start
	_, err = clientSocket.Write([]byte(clientConfig.KeyPair.ExportPublicKey()))
	if err != nil {
		t.Fatal("client can't write on socket")
	}
	clientSocket.Close()

}
