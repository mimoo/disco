<template>
	<section class="content">
		<h1 class="title"><i class="fa fa-wrench"></i> Hashing</h1>

		<h2><i class="fa fa-caret-right" aria-hidden="true"></i> Description</h2>

		<p>libdisco provides a simple hashing primitive that is not compatible with SHA-2 or SHA-3 or other hash functions. This means that the output you will get using libdisco's Hash function will be different. The use case and the security remain equivalent.</p>

		<p>To obtain the 256-bit hash of some input, perform the following:</p>

		<pre><code>input := []byte("hi, how are you?")
digest := libdisco.Hash(input, 32))</code></pre>

		<p>libdisco's hash function is more than just a hash function, it is actually an eXtendable Output Function (XOF) which provides a flexible output length. The minimum has been set to 32 bytes (256 bits) for security reasons, there is no practical maximum. The following example obtains an output of 1000 bytes:</p>

		<pre><code>input := []byte("a very long output")
digest := libdisco.Hash(input, 1000))</code></pre>


	</section>

</template>
