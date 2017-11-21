# LibDisco

The `libdisco` package contained in this folder is a **plug-and-play** secure protocol and library based on the [Noise protocol framework](http://noiseprotocol.org/). It has been implemented following the same patterns used in [crypto/tls](https://golang.org/pkg/crypto/tls/).

This has use cases close to TLS: it encrypts communications between a client and a server.

**This software is currently in beta. You are advised not to use it in production.**

## Documentation

Documentation can be found on [godoc](https://godoc.org/github.com/mimoo/disco/libdisco).

Usages can be found in this README.

## Usage

### Installation

Simply get the package:

```bash
$ go get github.com/mimoo/disco/libdisco
```

and import it in your application:

```go
package main

import(
  "github.com/mimoo/disco/libdisco"
)
```

### Configuration

A `libdisco.Config` is **mandatory** for setting up both clients and servers.

```
type Config struct {
  HandshakePattern noiseHandshakeType
  KeyPair          *KeyPair
  RemoteKey        []byte
  Prologue         []byte
  StaticPublicKeyProof []byte
  PublicKeyVerifier func(publicKey, proof []byte) bool
	PreSharedKey []byte
  HalfDuplex bool
}
```

**Handshake Pattern**: You will have to choose a *handshake pattern* from [the list of implemented patterns](https://godoc.org/github.com/mimoo/disco/libdisco#pkg-constants) first. We've included some explanations in the documentation and on this page, but the [Noise specification](http://noiseprotocol.org/libdisco.html#handshake-patterns)
contains the most amount of information about these. If the client and the server do not choose the same handshake pattern, they will not succeed in creating a secure channel. (If something is not clear, or if a pattern
has not been implemented, please use the issues on this repo to tell us.)

**KeyPair**: if the *handshake pattern* chosen requires the peer to be initialized
with a static key (because it will send its static key to the other peer during
the handshake), this should be filled with a X25519 `KeyPair` structure.
Several utility functions exist to create and load one, see `GenerateKeypair()`,
`GenerateAndSaveDiscoKeyPair()` and `LoadDiscoKeyPair()` in the [documentation](https://godoc.org/github.com/mimoo/disco/libdisco).

**RemoteKey**: if the *handshake pattern* chosen requires the peer to be initialized with the static key of the other peer (because it is supposed to know its peer's static key. Think about **public-key pinning**). This should be a 32-byte X25519 public key. A peer's public key can be obtained via the `KeyPair.ExtractPublicKey()` function.

**Prologue**: any messages that have been exchanged between a client and a server, prior to the encryption of the channel via Disco, can be authenticated via the *prologue*.
This means that if a man-in-the-middle attacker has removed, added or re-ordered messages prior to setting up a Disco channel, the client and the servers will not be able to setup a secure channel with Noise (and thus will inform both peers that the prologue information is not the same on both sides). To use this, simply concatenate all these messages (on both the client and the server) and pass them in the prologue value.

**StaticPublicKeyProof**: if the *handshake pattern* chosen has the peer send its static public key at some point in the handshake, the peer might need to provide a "proof" that the public key is "legit". For example, the `StaticPublicKeyProof` can be a signature over the peer's static public key from an authoritative root key. This "proof" will be sent as part of the handshake, possibly non-encrypted and visible to passive observers. More information is available in the [Disco Keys](#disco-keys) section.

**PublicKeyVerifier**: if the *handshake pattern* chosen has the peer receive
a static public key at some point in the handshake, then the peer needs a function to verify the validity of the received key. During the handshake a "proof" might have been sent. `PublicKeyVerifier` is a callback function that must be implemented by the application using Disco and that will be called on both the static public key that has been received and any payload that has been received so far (usually the payload sent by the previous `StaticPublicKeyProof` function). If this function returns true, the handshake will continue. Otherwise the handshake will fail. More information is available in the [Disco Keys](#disco-keys) section.

**PreSharedKey**: if the *handshake pattern* chosen requires both peers to be aware of a shared secret (of 32-byte), this pre-shared secret must be shared in the configuration prior to starting the handshake.

**HalfDuplex**: In some situation, one of the peer might be constrained by the size of its memory. In such scenarios, communication over a single writing channel might be a solution. Disco provides half-duplex channels where the client and the server take turn to write or read on the secure channel. For this to work this value must be set to `true` on both side of the connection. The server and client MUST NOT write or read on the secure channel at the same time.

### Server

Simply use the `Listen()` and `Accept()` paradigm. You then get
an object implementing the [net.Conn](https://golang.org/pkg/net/#Conn) interface.
You can then `Write()` and `Read()`.

The following example use the `Noise_NK` handshake where the client is not authenticated
and the server's key is known to the client in advance.

```go
package main

import (
	"fmt"

	"github.com/mimoo/disco/libdisco"
)

func main() {

	serverKeyPair := libdisco.GenerateKeypair(nil)

	serverConfig := libdisco.Config{
		HandshakePattern: libdisco.Noise_NK,
		KeyPair:          serverKeyPair,
	}

	listener, err := libdisco.Listen("tcp", "127.0.0.1:6666", &serverConfig)
	if err != nil {
		fmt.Println("cannot setup a listener on localhost:", err)
		return
	}
	addr := listener.Addr().String()
	fmt.Println("listening on:", addr)
	fmt.Println("server's public key:", serverKeyPair.ExportPublicKey())

	server, err := listener.Accept()
	if err != nil {
		fmt.Println("server cannot accept()")
		return
	}
	defer server.Close()

	buf := make([]byte, 100)
	for {
		n, err := server.Read(buf)
		if err != nil {
			fmt.Println("server can't read on socket", err)
			return
		}
		fmt.Println("server received some data:", string(buf[:n]))
	}
}
```

### Client

The client can simply use the `Dial()` paradigm using the public key of the server:

```go
package main

import (
	"encoding/hex"
	"fmt"

	"github.com/mimoo/disco/libdisco"
)

func main() {
  // replace this with the server's public key!
	serverKey, _ := hex.DecodeString("e424214ab16f56def7778e9a3d36d891221c4f5b38c8b2679ccbdaed5c27e735")
	clientConfig := libdisco.Config{
		HandshakePattern: libdisco.Noise_NK,
		RemoteKey:        serverKey,
	}

	client, err := libdisco.Dial("tcp", "127.0.0.1:6666", &clientConfig)
	if err != nil {
		fmt.Println("client can't connect to server:", err)
		return
	}
	defer client.Close()

	for {
		var in string
		fmt.Scanf("%s", &in)
		_, err = client.Write([]byte(in))
		if err != nil {
			fmt.Println("client can't write on socket:", err)
		}
	}
}
```

## Handshake Patterns Available

Currently, this package does not implement all the defined Noise handshake patterns.
If you are looking for a particular handshake pattern, please use the issues in this repo to request it.

### Noise_NX

This handshake pattern is similar to a typical **browser <-> HTTPS server** scenario where:

* the client does not authenticate itself
* the server authenticates its public key via a signature from an authoritative public key

**Why using this pattern?** If clients talk to several servers, while servers don't expect clients to authenticates themselves.

**Example of configuration**

For this, the **server** needs to be configured with a static public key, as well as a signature over that key


```go
serverConfig := libdisco.Config{
  HandshakePattern:     libdisco.Noise_NX,
  KeyPair:              serverKeyPair,
  StaticPublicKeyProof: proof,
}
```

As with our browser <-> HTTPS server scenario, a proof could be an X.509 certificate containing the `serverKeyPair` as well as a signature of the certificate from a certificate authority's public key. But to keep things simple, it could also just be a signature from an authoritative root key.

To help with this, this package comes with utility functions. See the section on the different [Disco keys](#disco-keys).

```go
// CreateStaticPublicKeyProof helps in creating a signature over the peer's static public key
// for that, it needs the private part of a signing root key pair that is trusted by the client.
proof := CreateStaticPublicKeyProof(rootKey.privateKey, peerKeyPair)
```

the **client** needs to be configured with a function capable of acting on the static public key the server will send to it as part of the handshake.
Without this, there are no guarantees that the static public key the server sends is "legit".

```go
clientConfig := libdisco.Config{
  HandshakePattern:  libdisco.Noise_NK,
  PublicKeyVerifier: someCallbackFunction,
}
```

Again, the package provides utility functions for this. See the section on the different [Disco keys](#disco-keys).

```go
// CreatePublicKeyVerifier helps in creating a callback function that will verify a signature
// for this it needs the public part of the signing root public key that we trust.
someCallbackFunction := CreatePublicKeyVerifier(rootKey.publicKey)
```

### Noise_XX

The Noise_XX handshake pattern is similar to the previous one, except that both the client and the server authenticates themselves via a static public key.
The proof can be created via the same utility functions and the same root key, or two different root keys. Here is an example of configuration:

**Why using this pattern?** if both the clients and servers talk to different clients and servers, while both needs the other peer to authenticate itself.

**Example of configuration**

server:

```go
// we load the private part of the root signing key
rootPrivateKey, err := libdisco.LoadDiscoRootPrivateKey("./discoRootPrivateKeyMama")
if err != nil {
  panic("didn't work")
}
rootPublicKey, err := LoadDiscoRootPublicKey("./discoRootPublicKeyPapa")
if err != nil {
  panic("didn't work")
}
// we compute our proof over our server's public key (stored in a KeyPair)
proof := libdisco.CreateStaticPublicKeyProof(rootPrivateKeyMama, serverKeyPair)
// we create our verifier
someCallbackFunction := CreatePublicKeyVerifier(rootPublicKeyPapa)
// we configure the server for Noise_XX
serverConfig := libdisco.Config{
  HandshakePattern:     libdisco.Noise_XX,
  KeyPair:              serverKeyPair,
  StaticPublicKeyProof: proof,
  PublicKeyVerifier:    someCallbackFunction,
}
```

client:

```go
// we load the public part of the root signing key
rootPrivateKey, err := libdisco.LoadDiscoRootPrivateKey("./discoRootPrivateKeyPapa")
if err != nil {
  panic("didn't work")
}
rootPublicKey, err := LoadDiscoRootPublicKey("./discoRootPublicKeyMama")
if err != nil {
  panic("didn't work")
}
// we compute our proof over our server's public key (stored in a KeyPair)
proof := libdisco.CreateStaticPublicKeyProof(rootPrivateKeyPapa, clientKeyPair)
// we create our verifier
someCallbackFunction := CreatePublicKeyVerifier(rootPublicKeyMama)
// we configure the client
clientConfig := libdisco.Config{
  HandshakePattern:     libdisco.Noise_XX,
  KeyPair:              clientKeyPair,
  StaticPublicKeyProof: proof,
  PublicKeyVerifier:    someCallbackFunction,
}
```

### Noise_NK

the Noise_NK handshake pattern is similar to mobile device applications connecting to webservers using public-key pinning.

The static public key is hardcoded on the client-side of the connection, because of this it is not "send" by the server during the connection, but still used as part of the cryptographic computations.

**Why using this pattern?** if you already know the server's static key and do not want to rely on an external root signing key and if the server doesn't expect the client to authenticates itself.

**Example of configuration**

server:

```go
serverConfig := libdisco.Config{
  HandshakePattern: libdisco.Noise_NK,
  KeyPair:          serverKeyPair,
}
```

client:

```go
clientConfig := libdisco.Config{
  HandshakePattern: libdisco.Noise_NK,
  remoteKey:        serverPublicKey, // replace this with the server's public key
}
```

### Noise_KK

The Noise_KK handshake pattern is similar to the Noise_NK pattern, except that both peers are authenticating themselves to each other.

**Why using this pattern?** If the client and the server are always the same two devices (meaning that the server always expect to talk to the same client).

**Example of configuration**

server:

```go
serverConfig := libdisco.Config{
  HandshakePattern: libdisco.Noise_KK,
  KeyPair:          serverKeyPair,
  remoteKey:        clientPublicKey, // replace this with the client's public key
}
```

client:

```go
clientConfig := libdisco.Config{
  HandshakePattern: libdisco.Noise_KK,
  KeyPair:          clientKeyPair,
  remoteKey:        serverPublicKey, // replace this with the server's public key
}
```

### Noise_N

Noise_N is a one-way handshake pattern. Meaning that only the client can send encrypted data to the server.

**Why using this pattern?** If clients always talk to a single server and the server never talks back to them. The server also doesn't require the client to authenticate itself.

**Example of configuration**

server:

```go
serverConfig := libdisco.Config{
  HandshakePattern: libdisco.Noise_N,
  KeyPair:          serverKeyPair,
}
```

client:

```go
clientConfig := libdisco.Config{
  HandshakePattern: libdisco.Noise_N,
  remoteKey:        serverPublicKey, // replace this with the server's public key
}
```

## Noise Keys

### The Different Keys

Disco makes use of several key pairs:

* Ephemeral keys, they are freshly created for each new client<->server connection.
* Static keys. Each one of the peers, the client and the server, can have their own long-term static key that they will consistently use in handshake patterns that require them (usually a pattern with a K, an X or an I in the name means that the client or/and the server will "make use" (not necessarily send) of a static key as part of the handshake)
* Root signing keys. These are authoritative keys that sign the static keys in patterns where static keys are being "sent" (not just used) as part of the handshake.

### Generation and Storage

**Ephemeral keys** are generated in the code and are never set manually anywhere, for this reason you do not have to worry about these and you can just ignore the fact that they exist.

**Static keys** can be generated via the `GenerateKeypair(nil)` function. They can be constructed from a private key with the same function. The package also provides some file utility functions:

* `KeyPair.ExportPublicKey()` retrieves the public part of a static key pair.
* `GenerateAndSaveDiscoKeyPair()` creates and saves a static key pair on disk.
* `LoadDiscoKeyPair(discoPrivateKeyPairFile()` loads a static key pair from such a file.

**Root signing keys** can be generated via the `GenerateAndSaveDiscoRootKeyPair()` function. As different peers might need different parts, the private and public parts of the key pair will be saved in different files. To retrieve them you can use `LoadDiscoRootPublicKey()` and `LoadDiscoRootPrivateKey()`.

### Configuration of Peers

Imagine a handshake pattern like [Noise_NX](#noise_nx) where only the server sends its static public key.

First let's create the root signing key:

```go
if err := libdisco.GenerateAndSaveDiscoRootKeyPair("./discoRootPrivateKey", "./discoRootPublicKey"); err != nil {
  panic("didn't work")
}
```

Now we can configure the server:

```go
// we load the private part of the root signing key
rootPrivateKey, err := libdisco.LoadDiscoRootPrivateKey("./discoRootPrivateKey")
if err != nil {
  panic("didn't work")
}
// we compute our proof over our server's public key (stored in a KeyPair)
proof := libdisco.CreateStaticPublicKeyProof(rootPrivateKey, serverKeyPair)
// we configure the server for Noise_NX
serverConfig := libdisco.Config{
  HandshakePattern:     libdisco.Noise_NX,
  KeyPair:              serverKeyPair,
  StaticPublicKeyProof: proof,
}
```

Once the `discoRootPublicKey` file has been passed to the client, we can configure it:

```go
// we load the public part of the root signing key
rootPublicKey, err := LoadDiscoRootPublicKey("./discoRootPublicKey")
if err != nil {
  panic("didn't work")
}
// we create our verifier
someCallbackFunction := CreatePublicKeyVerifier(rootPublicKey)
// we configure the client
clientConfig := libdisco.Config{
  HandshakePattern:  libdisco.Noise_NK,
  PublicKeyVerifier: someCallbackFunction,
}
```

And that's it!
