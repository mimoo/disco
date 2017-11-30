<template>
	<section class="content">
		<h1 class="title"><i class="fa fa-question"></i> Why using libdisco?</h1>

	    <ul>
	      <li>libdisco's source code is ~1000 lines of code. It makes it easy to audit and a pleasure to fit into tiny devices.</li>
	      <li>The protocol relies on the solid Noise protocol framework which is used by many others including WhatsApp, Wireguard, the Bitcoin Lightning Network, ...</li>
	      <li>The library relies only on two solid cryptographic primitives: curve25519 and SHA-3.</li>
	      <li>libdisco is flexible. libdisco supports many different ways of securely connecting two peers together while avoiding complex PKIs.</li>
	      <li>libdisco is versatile. While it allows you to securely link peers together, it is also a cryptographic library.</li>
	    </ul>

	    <article class="message is-danger" style="margin:20px 0">
	      <div class="message-header">
	        <p>Warning</p>
	      </div>
	      <div class="message-body">
	        Note that libdisco is still <strong>experimental</strong>. It has not been thoroughly reviewed and thus it is a pretty big "why you should not use libdisco in production"
	      </div>
	    </article>

	</section>
</template>