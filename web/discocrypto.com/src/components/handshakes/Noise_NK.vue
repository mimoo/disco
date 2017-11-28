<template>
	<section class="content">
		<h1 class="title is-1">{{pattern.name}}</h1>

		<h2><i class="fa fa-caret-right" aria-hidden="true"></i> Description</h2>

		<p v-html="pattern.description"></p>

		<h2><i class="fa fa-caret-right" aria-hidden="true"></i> Use cases</h2> 

		<p>if you already know the server's static key and do not want to rely on an external root signing key and if the server doesn't expect the client to authenticates itself.</p>

		<h2><i class="fa fa-caret-right" aria-hidden="true"></i> Example of configuration</h2>

		<h3>server:</h3>

		<pre><code>serverConfig := libdisco.Config{
  HandshakePattern: libdisco.Noise_NK,
  KeyPair:          serverKeyPair,
}</code></pre>

		<h3>client:</h3>

		<pre><code>clientConfig := libdisco.Config{
  HandshakePattern: libdisco.Noise_NK,
  remoteKey:        serverPublicKey, // replace this with the server's public key
}</code></pre>

		<h3>Security Considerations</h3>

		<ul>
			<li></li>
		</ul>

	</section>

</template>

<script>
import patterns from '@/assets/patterns.json';

export default {
	name: 'Noise_NK',
	data () {
		return {
			pattern: {}
		}
	},
	beforeMount () {
		patterns.forEach( (pattern) => {
			if(pattern.name == "Noise_NK") {
				this.pattern = pattern
			}
		})
	}
}
</script>