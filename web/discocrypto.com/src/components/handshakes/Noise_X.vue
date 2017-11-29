<template>
	<section class="content">
		<h1 class="title is-1">{{pattern.name}}</h1>

		<h2><i class="fa fa-caret-right" aria-hidden="true"></i> Description</h2>

		<p v-html="pattern.description"></p>

		<h2><i class="fa fa-caret-right" aria-hidden="true"></i> Use cases</h2> 



		<h2><i class="fa fa-caret-right" aria-hidden="true"></i> Example of configuration</h2>

		<h3>server:</h3>

		<pre><code>package main

import (
	"encoding/hex"
	"fmt"
	"net"
	"os"

	"github.com/mimoo/disco/libdisco"
)

func main() {
	// usage
	if len(os.Args) != 2 {
		fmt.Println("usage:go run server.go hex_root_public_key")
		return
	}

	// generating the server key pair
	serverKeyPair := libdisco.GenerateKeypair(nil)
	fmt.Println("server's public key:", serverKeyPair.ExportPublicKey())

	// retrieve root key
	rootPublicKey, err := hex.DecodeString(os.Args[1])
	if err != nil || len(rootPublicKey) != 32 {
		fmt.Println("public root key passed is not a 32-byte value in hexadecimal (", len(rootPublicKey), ")")
		return
	}

	// create a verifier for when we will receive the server's public key
	verifier := libdisco.CreatePublicKeyVerifier(rootPublicKey)

	// configuring the Disco connection
	// in which the client already knows the server's public key
	serverConfig := libdisco.Config{
		HandshakePattern:  libdisco.Noise_X,
		KeyPair:           serverKeyPair,
		PublicKeyVerifier: verifier,
	}

	// listen on port 6666
	listener, err := libdisco.Listen("tcp", "127.0.0.1:6666", &serverConfig)
	if err != nil {
		fmt.Println("cannot setup a listener on localhost:", err)
		return
	}
	addr := listener.Addr().String()
	fmt.Println("listening on:", addr)

	for {
		// accept a connection
		server, err := listener.Accept()
		if err != nil {
			fmt.Println("server cannot accept()")
			server.Close()
			continue
		}
		fmt.Println("server accepted connection from", server.RemoteAddr())
		// read what the socket has to say until connection is closed
		go func(server net.Conn) {
			buf := make([]byte, 100)
			for {
				n, err := server.Read(buf)
				if err != nil {
					fmt.Println("server can't read on socket for", server.RemoteAddr(), ":", err)
					break
				}
				fmt.Println("received data from", server.RemoteAddr(), ":", string(buf[:n]))
			}
			fmt.Println("shutting down the connection with", server.RemoteAddr())
			server.Close()
		}(server)

	}

}
</code></pre>

		<h3>client:</h3>

		<pre><code>package main

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"os"

	"github.com/mimoo/disco/libdisco"
)

func main() {

	//
	// run `go run client.go gen` to generate the static key of the client
	//
	if len(os.Args) == 2 && os.Args[1] == "setup" {

		// generating the client's keypair
		clientKeyPair, err := libdisco.GenerateAndSaveDiscoKeyPair("./clientKeyPair")
		if err != nil {
			panic("couldn't generate and save the client's key pair")
		}

		// displaying the public part
		fmt.Println("generated the client static public key successfuly. Client's public key:")
		fmt.Println(hex.EncodeToString(clientKeyPair.PublicKey[:]))

		return
	}

	//
	// run `go run client.go connect hex_proof hex_server_static_public_key` to connect to a server
	//
	if len(os.Args) == 4 && os.Args[1] == "connect" {

		// load the client's keypair
		clientKeyPair, err := libdisco.LoadDiscoKeyPair("./clientkeyPair")
		if err != nil {
			fmt.Println("couldn't load the client's key pair")
			return
		}

		// retrieve server's static public key
		serverPublicKey, err := hex.DecodeString(os.Args[3])
		if err != nil || len(serverPublicKey) != 32 {
			fmt.Println("server's static public key passed is not a 32-byte value in hexadecimal (", len(serverPublicKey), ")")
			return
		}

		// retrieve signature/proof
		proof, err := hex.DecodeString(os.Args[2])
		if err != nil || len(proof) != 64 {
			fmt.Println("proof passed is not a 64-byte value in hexadecimal (", len(proof), ")")
			return
		}

		// configure the Disco connection with Noise_XX
		clientConfig := libdisco.Config{
			KeyPair:              clientKeyPair,
			RemoteKey:            serverPublicKey,
			HandshakePattern:     libdisco.Noise_X,
			StaticPublicKeyProof: proof,
		}

		// Dial the port 6666 of localhost
		client, err := libdisco.Dial("tcp", "127.0.0.1:6666", &clientConfig)
		if err != nil {
			fmt.Println("client can't connect to server:", err)
			return
		}
		defer client.Close()
		fmt.Println("connected to", client.RemoteAddr())

		// write whatever stdin has to say to the socket
		scanner := bufio.NewScanner(os.Stdin)
		for {
			scanner.Scan()
			_, err = client.Write([]byte(scanner.Text()))
			if err != nil {
				fmt.Println("client can't write on socket:", err)
			}
		}

		return
	}

	// usage
	fmt.Println("read source code to find out usage")
	return
}
</code></pre>

		<h3>Security Considerations</h3>

	</section>

</template>

<script>
import patterns from '@/assets/patterns.json';

export default {
	name: 'Noise_X',
	data () {
		return {
			pattern: {}
		}
	},
	beforeMount () {
		patterns.forEach( (pattern) => {
			if(pattern.name == "Noise_X") {
				this.pattern = pattern
			}
		})
	}
}
</script>