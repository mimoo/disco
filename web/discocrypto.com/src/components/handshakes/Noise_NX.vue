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