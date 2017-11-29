<template>
	<section class="content">
		<h1 class="title is-1">Noise_NNpsk2</h1>

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
		fmt.Println("usage: go run client.go hex_shared_secret")
		return
	}

	// retrieve the server's public key from an argument
	sharedSecret, _ := hex.DecodeString(os.Args[1])

	// configuring the Disco connection
	serverConfig := libdisco.Config{
		HandshakePattern: libdisco.Noise_NNpsk2,
		PreSharedKey:     sharedSecret,
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
	// usage
	if len(os.Args) != 2 {
		fmt.Println("usage: go run client.go hex_shared_secret")
		return
	}

	// retrieve the server's public key from an argument
	sharedSecret, _ := hex.DecodeString(os.Args[1])

	// configure the Disco connection
	clientConfig := libdisco.Config{
		HandshakePattern: libdisco.Noise_NNpsk2,
		PreSharedKey:     sharedSecret,
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


	</section>

</template>

<script>
import patterns from '@/assets/patterns.json';

export default {
	name: 'Noise_NNpsk2',
	data () {
		return {
			pattern: {}
		}
	},
	beforeMount () {
		patterns.forEach( (pattern) => {
			if(pattern.name == "Noise_NNpsk2") {
				this.pattern = pattern
			}
		})
	}
}
</script>