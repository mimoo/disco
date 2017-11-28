<template>
  <div id="app">

    <header class="section">
      <div class="container">
        <nav class="level">
          <!-- Left side -->
          <div class="level-left">
            <div class="level-item">
              <div class="navbar-brand">
                <a class="navbar-item" href="/">
                  <img src="/static/discoblue.png" alt="Disco: a modern plug-and-play secure protocol and a cryptographic library">
                </a>
              </div>
              <h1>libdisco</h1>
            </div>
          </div>
          <!-- Right side -->
          <div class="level-right">
            <p class="level-item"><router-link to="/">Home</router-link></p>
            <p class="level-item"><router-link to="/get_started" class="button is-success">Get Started</router-link></p>
            <p class="level-item"><router-link to="/protocol/Overview">Protocol</router-link></p>
            <p class="level-item"><router-link to="/library/Overview">Cryptographic Library</router-link></p>
            <p class="level-item"><a href="https://github.com/mimoo/disco/">Source Code</a></p>
            <p class="level-item"><a href="https://www.cryptologie.net/contact">Contact</a></p>
          </div>
        </nav>
      </div>
    </header>

    <section class="section">
      <div class="container">
        <div class="columns">
          <div class="column is-one-quarter">
            <aside class="menu">
              <p class="menu-label">
                General
              </p>
              <ul class="menu-list">
                <li><router-link to="/get_started">Get Started</router-link></li>
              </ul>
              <p class="menu-label">
                Protocol
              </p>
              <ul class="menu-list">
                <li><router-link to="/protocol/Overview">Overview</router-link>
                  <ul>
                    <li v-for="pattern in patterns"><router-link :to="'/protocol/' + pattern.name">{{pattern.name}}</router-link></li>
                  </ul>
                </li>
                <li>
                  <a href="disco.html">Specification</a>
                </li>
              </ul>
              <p class="menu-label">
                Cryptographic Library
              </p>
              <ul class="menu-list">
                <li><router-link to="/library/Overview">Overview</router-link></li>
                  <!--
                  <li><a>Hashing</a></li>
                  <li><a>Encrypting</a></li>
                  <li><a>Authenticating</a></li>
                  <li><a>Deriving Keys</a></li>
                  <li><a>Signing</a></li>
                  <li><a>Password Hashing</a></li>
                -->
              </ul>
            </aside>
          </div> <!-- .column -->

          <div class="column">
            <router-view/>
          </div>  <!-- .column -->

        </div> <!-- .columns -->
      </div> <!-- .container -->
    </section>

    <footer class="footer">
      <div class="container">
        <div class="content has-text-centered">
          <p>
            <strong>Disco</strong> and <strong>libdisco</strong> by <a href="http://www.cryptologie.net">David Wong</a>.
          </p>
        </div>
      </div>
    </footer>
  </div>
</template>

<script>
export default {
  name: 'app'
}
</script>

<style>
  @import url('https://fonts.googleapis.com/css?family=Open+Sans:300,400,700,800');
  @import url('https://fonts.googleapis.com/css?family=Work+Sans:900');
  @import url('https://fonts.googleapis.com/css?family=Roboto+Mono');

  * {
    box-sizing: border-box;
    font-family: 'Open Sans', sans-serif;
  }

  body {
    margin: 0;
    border-top: 10px #209cee solid;
  }

  header.section{
    padding:30px 0 0;
  }

  .hero .title{
    margin-bottom:40px;
  }
  .hero .title strong{
    font-weight:800;
  }
  .hero .subtitle {
    font-weight:300;
    line-height:37px;
  }

  .main_list span {
    border-bottom:1px solid black;
  }

  .navbar-brand img {
    width:50px;
    max-height:none;
  }
  header h1 {
    font-family: 'Work Sans', sans-serif;
    font-size:30px;
    color:#2e315d;
  }
  pre, code, code span {
    font-family:"Roboto Mono" !important;
    white-space:pre-wrap;
  }

  .box span{
     margin:0 5px 10px;

  }
</style>
<script>
  import patterns from '@/assets/patterns.json';
  window.hljs = require('highlight.js')

export default {
  data () {
    return {
      patterns: []
    }
  },
  beforeMount () {
    this.patterns = patterns
  },
  mounted () {
    hljs.initHighlightingOnLoad()
  },
  updated() {
    document.querySelectorAll("pre").forEach( a => {
      hljs.highlightBlock(a)
      } )     
  },
}
</script>