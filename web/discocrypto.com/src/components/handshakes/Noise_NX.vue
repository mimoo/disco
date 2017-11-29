<template>
	<section class="content">
		<h1 class="title is-1">{{pattern.name}}</h1>

		<h2><i class="fa fa-caret-right" aria-hidden="true"></i> Description</h2>

		<p v-html="pattern.description"></p>

		<h2><i class="fa fa-caret-right" aria-hidden="true"></i> Use cases</h2> 

		<p>If clients talk to several servers, while servers don't expect clients to authenticates themselves.</p>

		<h2><i class="fa fa-caret-right" aria-hidden="true"></i> Example of configuration</h2>

		<h3>server:</h3>

		<p>For this, the server needs to be configured with a static public key, as well as a signature over that key</p>

		<pre><code>serverConfig := libdisco.Config{
  HandshakePattern:     libdisco.Noise_NX,
  KeyPair:              serverKeyPair,
  StaticPublicKeyProof: proof,
}</code></pre>

		<p>As with our browser ↔ HTTPS server scenario, a proof could be an X.509 certificate containing the serverKeyPair as well as a signature of the certificate from a certificate authority's public key. But to keep things simple, it could also just be a signature from an authoritative root key.</p>

		<p>To help with this, this package comes with utility functions. See the section on the different Disco keys.</p>

		<pre><code>// CreateStaticPublicKeyProof helps in creating a signature over the peer's static public key
// for that, it needs the private part of a signing root key pair that is trusted by the client.
proof := CreateStaticPublicKeyProof(rootKey.privateKey, peerKeyPair)
</code></pre>

		<p>Finally, the full example for the server:</p>

		<pre><code>package main

import (
	"encoding/hex"
	"fmt"
	"net"
	"os"

	"github.com/mimoo/disco/libdisco"
)

func main() {

	//
	// run `go run server.go gen` to generate the static keypair of the server
	//
	if len(os.Args) == 2 && os.Args[1] == "setup" {

		// generating the server's keypair
		serverKeyPair, err := libdisco.GenerateAndSaveDiscoKeyPair("./serverKeyPair")
		if err != nil {
			panic("couldn't generate and save the server's key pair")
		}

		// displaying the public part
		fmt.Println("generated the server static public key successfuly. server's public key:")
		fmt.Println(hex.EncodeToString(serverKeyPair.PublicKey[:]))

		return
	}

	//
	// run `go run server.go accept hex_proof` to accept connections
	//
	if len(os.Args) == 3 && os.Args[1] == "accept" {

		// load the server's keypair
		serverKeyPair, err := libdisco.LoadDiscoKeyPair("./serverkeyPair")
		if err != nil {
			fmt.Println("couldn't load the server's key pair")
			return
		}

		// retrieve signature/proof
		proof, err := hex.DecodeString(os.Args[2])
		if err != nil || len(proof) != 64 {
			fmt.Println("proof passed is not a 64-byte value in hexadecimal (", len(proof), ")")
			return
		}

		// configure the Disco connection
		serverConfig := libdisco.Config{
			KeyPair:              serverKeyPair,
			HandshakePattern:     libdisco.Noise_NX,
			StaticPublicKeyProof: proof,
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

		return
	}

	// usage
	fmt.Println("read source code to find out usage")
	return
}
</code></pre>

		<h3>client:</h3>

		<p>the client needs to be configured with a function capable of acting on the static public key the server will send to it as part of the handshake. Without this, there are no guarantees that the static public key the server sends is "legit".</p>

		<pre><code>clientConfig := libdisco.Config{
  HandshakePattern:  libdisco.Noise_NK,
  PublicKeyVerifier: someCallbackFunction,
}</code></pre>

		<p>Again, the package provides utility functions for this. See the section on the different Disco keys.</p>

		<pre><code>// CreatePublicKeyVerifier helps in creating a callback function that will verify a signature
// for this it needs the public part of the signing root public key that we trust.
someCallbackFunction := CreatePublicKeyVerifier(rootKey.publicKey)</code></pre>

		<p>Finally the full example for a client:</p>

		<pre><code>package main

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"os"

	"github.com/mimoo/disco/libdisco"
)

func main() {

	if len(os.Args) != 2 {
		fmt.Println("usage: go run client.go hex_root_public_key")
	}

	// retrieve root public key
	rootPublicKey, err := hex.DecodeString(os.Args[1])
	if err != nil || len(rootPublicKey) != 32 {
		fmt.Println("public root key passed is not a 32-byte value in hexadecimal (", len(rootPublicKey), ")")
		return
	}

	// create a verifier for when we will receive the server's public key
	verifier := libdisco.CreatePublicKeyVerifier(rootPublicKey)

	// configure the Disco connection
	clientConfig := libdisco.Config{
		HandshakePattern:  libdisco.Noise_NX,
		PublicKeyVerifier: verifier,
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

}
</code></pre>

		<h3>Security Considerations</h3>

		<ul>
			<li></li>
		</ul>

	</section>

</template>

<script>
import patterns from '@/assets/patterns.json';

export default {
	name: 'Noise_NX',
	data () {
		return {
			pattern: {}
		}
	},
	beforeMount () {
		patterns.forEach( (pattern) => {
			if(pattern.name == "Noise_NX") {
				this.pattern = pattern
			}
		})
	}
}
</script>