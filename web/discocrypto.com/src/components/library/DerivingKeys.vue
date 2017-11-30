<template>
	<section class="content">
		<h1 class="title"><i class="fa fa-wrench"></i> Deriving Keys</h1>

		<h2><i class="fa fa-caret-right" aria-hidden="true"></i> Description</h2>

		<pre><code>input := []byte("hi, how are you?")
keys := libdisco.DeriveKeys(input, 64))
key1 := keys[:32]
key2 := keys[32:]</code></pre>

	</section>

</template>
