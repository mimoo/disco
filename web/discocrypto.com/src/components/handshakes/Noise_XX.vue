<template>
	<section class="content">
		<h1 class="title is-1">Noise_XX</h1>

		<h2><i class="fa fa-caret-right" aria-hidden="true"></i> Description</h2>

		<p v-html="pattern.description"></p>

		<h2><i class="fa fa-caret-right" aria-hidden="true"></i> Use cases</h2> 

		<p>Any <code>X</code> pattern where a peer authenticate itself via the signature of an authoritative key (like the <code>Noise_XX</code> pattern) is useful when the other peer doesn't know in advance what peer it will communicate to.</p>

		<p>This means that <code>Noise_XX</code> is a good candidate for setups where many clients try to connect to many servers, and none of the clients or servers share the same static key.</p>

		<p>Like any <code>X</code> pattern where a static key is sent, the peer needs to also send a proof which is typically a signature over its static public key from an authoritative key (a root key). With <code>Noise_XX</code>, both peers need to provide a proof, and they both need to verify each other's proof. libdisco supplies helpers to achieve both functionalities, the following examples demonstrate how to use them.</p>

		<h2><i class="fa fa-caret-right" aria-hidden="true"></i> Example of configuration</h2>

		<p>In the following example of configuration, <strong>libdisco's helper functions</strong> are used to create proofs and verify them, as well as to <a href="https://godoc.org/github.com/mimoo/disco/libdisco#GenerateAndSaveDiscoRootKeyPair">generate the root key</a> which can create these proofs. Notice that the configuration is the same for both peers as we're using a single root key.</p>

		<article class="message is-danger">
		  <div class="message-header">
		    <p>Security Consideration</p>
		  </div>
		  <div class="message-body">
		    Note that in this example the private part of the root signing key is loaded on both peers. In practice, this and the computation of the proof should be done on a different machine.
		  </div>
		</article>

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

	//
	// run `go run server.go gen` to generate the static key of the server
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
	// run `go run server.go accept hex_proof hex_root_public_key` to connect to a server
	//
	if len(os.Args) == 4 && os.Args[1] == "accept" {

		// load the server's keypair
		serverKeyPair, err := libdisco.LoadDiscoKeyPair("./serverkeyPair")
		if err != nil {
			fmt.Println("couldn't load the server's key pair")
			return
		}

		// retrieve root key
		rootPublicKey, err := hex.DecodeString(os.Args[3])
		if err != nil || len(rootPublicKey) != 32 {
			fmt.Println("public root key passed is not a 32-byte value in hexadecimal (", len(rootPublicKey), ")")
			return
		}

		// create a verifier for when we will receive the server's public key
		verifier := libdisco.CreatePublicKeyVerifier(rootPublicKey)

		// retrieve signature/proof
		proof, err := hex.DecodeString(os.Args[2])
		if err != nil || len(proof) != 64 {
			fmt.Println("proof passed is not a 64-byte value in hexadecimal (", len(proof), ")")
			return
		}

		// configure the Disco connection with Noise_XX
		serverConfig := libdisco.Config{
			KeyPair:              serverKeyPair,
			HandshakePattern:     libdisco.Noise_XX,
			PublicKeyVerifier:    verifier,
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
	// run `go run client.go connect hex_proof hex_root_public_key` to connect to a server
	//
	if len(os.Args) == 4 && os.Args[1] == "connect" {

		// load the client's keypair
		clientKeyPair, err := libdisco.LoadDiscoKeyPair("./clientkeyPair")
		if err != nil {
			fmt.Println("couldn't load the client's key pair")
			return
		}

		// retrieve root key
		rootPublicKey, err := hex.DecodeString(os.Args[3])
		if err != nil || len(rootPublicKey) != 32 {
			fmt.Println("public root key passed is not a 32-byte value in hexadecimal (", len(rootPublicKey), ")")
			return
		}

		// create a verifier for when we will receive the server's public key
		verifier := libdisco.CreatePublicKeyVerifier(rootPublicKey)

		// retrieve signature/proof
		proof, err := hex.DecodeString(os.Args[2])
		if err != nil || len(proof) != 64 {
			fmt.Println("proof passed is not a 64-byte value in hexadecimal (", len(proof), ")")
			return
		}

		// configure the Disco connection with Noise_XX
		clientConfig := libdisco.Config{
			KeyPair:              clientKeyPair,
			HandshakePattern:     libdisco.Noise_XX,
			PublicKeyVerifier:    verifier,
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

	<p>This handshake pattern is tricky (like any <code>X</code>-type handshakes) as it requires a Public Key Infrastructure (PKI) where:</p>

	<ul>
		<li>the root signing key is securely generated and kept in a secure location (this is often done via a <a href="https://en.wikipedia.org/wiki/Key_ceremony">key ceremony</a>)</li>
		<li>the "proofs" (a signature from the root key on a peer's static public key) are generated and passed to the peer in a secure manner</li>
		<li>keys might need to be revoked. This mean that an additional system needs to detect revokations.</li>
	</ul>

	</section>

</template>

<script>
	import patterns from '@/assets/patterns.json';
export default {
    name: 'Noise_XX',
    data () {
    	return {
    		pattern: {}
    	}
    },
    beforeMount () {
    	patterns.forEach( (pattern) => {
    		if(pattern.name == "Noise_XX") {
    			this.pattern = pattern
    		}
    	})
    }
  }
</script>