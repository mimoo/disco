<template>
  <section class="content">
    <section class="hero is-info is-bold">
      <div class="hero-body">
        <h1 class="title">
          <strong>libdisco</strong>
        </h1>
        <h2 class="subtitle">
          libdisco is a <strong>modern plug-and-play secure protocol</strong> and a <strong>cryptographic library</strong> implemented in <strong>1000 lines of code</strong> in <strong>Golang</strong>. It offers different ways of securely connecting peers together, as well as different cryptographic primitives for all of an application's needs.
        </h2>
      </div>
    </section>

    <article class="message is-danger" style="margin:20px 0">
      <div class="message-header">
        <p>Warning</p>
      </div>
      <div class="message-body">
        libdisco is <strong>experimental</strong>. It still has not been thoroughly reviewed and thus should not be used in production.
      </div>
    </article>

    <p>
      <strong>libdisco</strong> is a library built by merging the <a href="http://noiseprotocol.org">Noise protocol framework</a> and the <a href="https://strobe.sourceforge.io">Strobe protocol framework</a>. This means that it supports a subset of Noise's handshakes while offering the cryptographic primitive Strobe has to offer. In other words, you can use libdisco to securely connect peers together, or to do basic cryptographic operations like hashing or encrypting.</p>

    <!--          If you want to know more you can read the whitepaper or watch this video -->

    <p>
      <ul class="main_list">
        <li>The <span>secure protocol parts</span> are based on the <a href="/disco.html"><i class="fa fa-file-text-o" aria-hidden="true"></i> Disco specification</a> which extends the <strong>Noise protocol framework</strong>.</li>
        <li>The <span>symmetric cryptographic primitives</span> are all based on the <strong>Strobe protocol framework</strong> which only relies on the <strong>SHA-3</strong> permutation (called <strong>keccak-f</strong>).</li>
        <li>The <span>asymmetric cryptographic primitives</span> (<strong>X25519</strong> and <strong>ed25519</strong>) are based on the <a href="https://golang.org/">golang</a> standard library.</li>
      </ul>
    </p>

    <p>To make use of the <strong><i class="fa fa-exchange" aria-hidden="true"></i>
    protocol parts</strong>, you must first choose how you want to authenticate the connection. For that, it's easy! We have made a <strong>small quizz</strong> for you bellow, but if you already know what you want you can directly click on your favorite way of doing this in the menu under "protocol" (Noise_NK, Noise_XX, ...) and copy the usage examples.</p>

    <Quizz></Quizz>

    <p>To make use of the <strong><i class="fa fa-wrench" aria-hidden="true"></i>
    cryptographic library</strong>, check our <router-link to="/library/Overview">overview here</router-link> or directly access them through the menu on the left.</p>

    <p>If you want help, head to the <a href="https://github.com/mimoo/disco/issues"><i class="fa fa-question" aria-hidden="true"></i>
    issues on github</a>. If you want to stay tuned on what we're doing, we don't have a mailing list but we have better: <a href="https://www.reddit.com/r/discocrypto/"><i class="fa fa-envelope-o" aria-hidden="true"></i>
    a subreddit over at r/discocrypto</a>.</p>
  </section>
</template>

<style scoped>
  .title{
    border-bottom:0;
  }
</style>

<script>
  import Quizz from './Quizz'

  export default {
    name: 'LandingPage',
    components: {
      Quizz
    }
  }
</script>
