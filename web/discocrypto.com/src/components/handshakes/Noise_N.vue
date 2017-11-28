<template>
	<section class="content">
		<h1 class="title is-1">{{pattern.name}}</h1>

		<h2><i class="fa fa-caret-right" aria-hidden="true"></i> Description</h2>

		<p v-html="pattern.description"></p>

		<h2><i class="fa fa-caret-right" aria-hidden="true"></i> Use cases</h2> 

		<p>If clients always talk to a single server and the server never talks back to them. The server also doesn't require the client to authenticate itself.</p>
	
		<h2><i class="fa fa-caret-right" aria-hidden="true"></i> Example of configuration</h2>

		<h3>server:</h3>

		<pre><code>serverConfig := libdisco.Config{
  HandshakePattern: libdisco.Noise_N,
  KeyPair:          serverKeyPair,
}</code></pre>

		<h3>client:</h3>

		<pre><code>clientConfig := libdisco.Config{
  HandshakePattern: libdisco.Noise_N,
  remoteKey:        serverPublicKey, // replace this with the server's public key
}</code></pre>

		<h3>Security Considerations</h3>

		<ul>
			<li>the pre-shared key must be safely stored on both endpoints.</li>
			<li>you usually do not want to share a single pre-shared key over many endpoints, better ways to do this usually involve a PKI. See <router-link to="/handshakes/Noise_XX">Noise_XX</router-link>.</li>
		</ul>

	</section>

</template>

<script>
import patterns from '@/assets/patterns.json';

export default {
	name: 'Noise_N',
	data () {
		return {
			pattern: {}
		}
	},
	beforeMount () {
		patterns.forEach( (pattern) => {
			if(pattern.name == "Noise_N") {
				this.pattern = pattern
			}
		})
	}
}
</script>