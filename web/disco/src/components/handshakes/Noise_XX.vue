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

		<pre><code>// we load the private part of the root signing key
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
someCallbackFunction := libdisco.CreatePublicKeyVerifier(rootPublicKeyPapa)
// we configure the server for Noise_XX
serverConfig := libdisco.Config{
	HandshakePattern:     libdisco.Noise_XX,
	KeyPair:              serverKeyPair,
	StaticPublicKeyProof: proof,
	PublicKeyVerifier:    someCallbackFunction,
}</code></pre>

<h3>client:</h3>

<pre><code>// we load the root signing key
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
someCallbackFunction := libdisco.CreatePublicKeyVerifier(rootPublicKeyMama)
// we configure the client
clientConfig := libdisco.Config{
	HandshakePattern:     libdisco.Noise_XX,
	KeyPair:              clientKeyPair,
	StaticPublicKeyProof: proof,
	PublicKeyVerifier:    someCallbackFunction,
}</code></pre>

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