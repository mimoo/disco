<template>
	<section class="content">
		<h1 class="title is-1">Disco Keys</h1>

		<h2><i class="fa fa-caret-right" aria-hidden="true"></i> The Different Keys</h2> 

		<p>Disco makes use of several key pairs:</p>

		<ul>
<li>Ephemeral keys, they are freshly created for each new client ↔ server connection.</li>
<li>Static keys. Each one of the peers, the client and the server, can have their own long-term static key that they will consistently use in handshake patterns that require them (usually a pattern with a K, an X or an I in the name means that the client or/and the server will "make use" (not necessarily send) of a static key as part of the handshake)</li>
<li>Root signing keys. These are authoritative keys that sign the static keys in patterns where static keys are being "sent" (not just used) as part of the handshake.</li>
		</ul>

		<h2><i class="fa fa-caret-right" aria-hidden="true"></i> Generation and Storage</h2> 

<p>
		<strong>Ephemeral keys</strong> are generated in the code and are never set manually anywhere, for this reason you do not have to worry about these and you can just ignore the fact that they exist.
</p>
<p>
		<strong>Static keys</strong> can be generated via the GenerateKeypair(nil) function. They can be constructed from a private key with the same function. The package also provides some file utility functions:
</p>
		<ul>
			<li><code>KeyPair.ExportPublicKey()</code> retrieves the public part of a static key pair.</li>
			<li><code>GenerateAndSaveDiscoKeyPair()</code> creates and saves a static key pair on disk.</li>
			<li><code>LoadDiscoKeyPair(discoPrivateKeyPairFile()</code> loads a static key pair from such a file.</li>
		</ul>
<p>
		<strong>Root signing keys</strong> can be generated via the <code>GenerateAndSaveDiscoRootKeyPair()</code> function. As different peers might need different parts, the private and public parts of the key pair will be saved in different files. To retrieve them you can use <code>LoadDiscoRootPublicKey()</code> and <code>LoadDiscoRootPrivateKey()</code>.
</p>


		<h2><i class="fa fa-caret-right" aria-hidden="true"></i> Configuration of Peers</h2>

		<p>Imagine a handshake pattern like Noise_NX where only the server sends its static public key.</p>

		<p>First let's create the root signing key:</p>

		<pre><code>if err := libdisco.GenerateAndSaveDiscoRootKeyPair("./discoRootPrivateKey", "./discoRootPublicKey"); err != nil {
  panic("didn't work")
}</code></pre>

		<p>Now we can configure the server:</p>

		<pre><code>// we load the private part of the root signing key
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
}</code></pre>

		<p>Once the <code>discoRootPublicKey</code> file has been passed to the client, we can configure it:</p>

		<pre><code>// we load the public part of the root signing key
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
</code></pre>

	<p>And that's it!</p>


	</section>

</template>

<script>
import patterns from '@/assets/patterns.json';

export default {
	name: 'Noise_KK',
	data () {
		return {
			pattern: {}
		}
	},
	beforeMount () {
		patterns.forEach( (pattern) => {
			if(pattern.name == "Noise_KK") {
				this.pattern = pattern
			}
		})
	}
}
</script>