package libdisco

//
// Handshake Patterns
//

type noiseHandshakeType int8

const (
	// NoiseUnknown is for specifying an unknown pattern
	NoiseUnknown noiseHandshakeType = iota
	// NoiseN is a one-way pattern where a client can send
	// data to a server with a known static key. The server
	// can only receive data and cannot reply back.
	NoiseN

	// NoiseK is a one-way pattern where a client can send
	// data to a server with a known static key. The server
	// can only receive data and cannot reply back. The server
	// authenticates the client via a known key.
	NoiseK

	// NoiseX is a one-way pattern where a client can send
	// data to a server with a known static key. The server
	// can only receive data and cannot reply back. The server
	// authenticates the client via a key transmitted as part
	// of the handshake.
	NoiseX

	// NoiseKK is a pattern where both the client static key and the
	// server static key are known.
	NoiseKK

	// NoiseNX is a "HTTPS"-like pattern where the client is
	// not authenticated, and the static public key of the server
	// is transmitted during the handshake. It is the responsability of the client to validate the received key properly.
	NoiseNX

	// NoiseNK is a "Public Key Pinning"-like pattern where the client
	// is not authenticated, and the static public key of the server
	// is already known.
	NoiseNK

	// NoiseXX is a pattern where both static keys are transmitted.
	// It is the responsability of the server and of the client to
	// validate the received keys properly.
	NoiseXX

	// NoiseKX Not documented
	NoiseKX
	// NoiseXK Not documented
	NoiseXK
	// NoiseIK Not documented
	NoiseIK
	// NoiseIX Not documented
	NoiseIX
	// NoiseNNpsk2 Not documented
	NoiseNNpsk2

	// NoiseNN Not implemented
	NoiseNN
	// NoiseKN Not implemented
	NoiseKN
	// NoiseXN Not implemented
	NoiseXN
	// NoiseIN Not implemented
	NoiseIN
)

type token uint8

const (
	tokenUnknown token = iota
	token_e
	token_s
	token_es
	token_se
	token_ss
	token_ee
	token_psk
)

type messagePattern []token

type handshakePattern struct {
	name               string
	preMessagePatterns []messagePattern
	messagePatterns    []messagePattern
}

// TODO: add more patterns
var patterns = map[noiseHandshakeType]handshakePattern{

	// 7.2. One-way patterns

	NoiseN: handshakePattern{
		name: "N",
		preMessagePatterns: []messagePattern{
			messagePattern{},        // →
			messagePattern{token_s}, // ←
		},
		messagePatterns: []messagePattern{
			messagePattern{token_e, token_es}, // →
		},
	},

	/*
		K(s, rs):
		  -> s
		  <- s
		  ...
		  -> e, es, ss
	*/
	NoiseK: handshakePattern{
		name: "K",
		preMessagePatterns: []messagePattern{
			messagePattern{token_s}, // →
			messagePattern{token_s}, // ←
		},
		messagePatterns: []messagePattern{
			messagePattern{token_e, token_es, token_ss}, // →
		},
	},
	/*
		X(s, rs):
		 <- s
		 ...
		 -> e, es, s, ss
	*/
	NoiseX: handshakePattern{
		name: "X",
		preMessagePatterns: []messagePattern{
			messagePattern{},        // →
			messagePattern{token_s}, // ←
		},
		messagePatterns: []messagePattern{
			messagePattern{token_e, token_es, token_s, token_ss}, // →
		},
	},
	//
	// 7.3. Interactive patterns
	//
	NoiseKK: handshakePattern{
		name: "KK",
		preMessagePatterns: []messagePattern{
			messagePattern{token_s}, // →
			messagePattern{token_s}, // ←
		},
		messagePatterns: []messagePattern{
			messagePattern{token_e, token_es, token_ss}, // →
			messagePattern{token_e, token_ee, token_se}, // ←
		},
	},

	NoiseNX: handshakePattern{
		name: "NX",
		preMessagePatterns: []messagePattern{
			messagePattern{}, // →
			messagePattern{}, // ←
		},
		messagePatterns: []messagePattern{
			messagePattern{token_e},                              // →
			messagePattern{token_e, token_ee, token_s, token_es}, // ←
		},
	},

	NoiseNK: handshakePattern{
		name: "NK",
		preMessagePatterns: []messagePattern{
			messagePattern{},        // →
			messagePattern{token_s}, // ←
		},
		messagePatterns: []messagePattern{
			messagePattern{token_e, token_es}, // →
			messagePattern{token_e, token_ee}, // ←
		},
	},

	NoiseXX: handshakePattern{
		name: "XX",
		preMessagePatterns: []messagePattern{
			messagePattern{}, // →
			messagePattern{}, // ←
		},
		messagePatterns: []messagePattern{
			messagePattern{token_e},                              // →
			messagePattern{token_e, token_ee, token_s, token_es}, // ←
			messagePattern{token_s, token_se},                    // →
		},
	},

	/*
			KX(s, rs):
		      -> s
		      ...
		      -> e
		      <- e, ee, se, s, es
	*/
	NoiseKX: handshakePattern{
		name: "KX",
		preMessagePatterns: []messagePattern{
			messagePattern{token_s}, // →
			messagePattern{},        // ←
		},
		messagePatterns: []messagePattern{
			messagePattern{token_e}, // →
			messagePattern{token_e, token_ee, token_se, token_s, token_es}, // ←
		},
	},
	/*
			XK(s, rs):
		  <- s
		  ...
		  -> e, es
		  <- e, ee
		  -> s, se
	*/
	NoiseXK: handshakePattern{
		name: "XK",
		preMessagePatterns: []messagePattern{
			messagePattern{},        // →
			messagePattern{token_s}, // ←
		},
		messagePatterns: []messagePattern{
			messagePattern{token_e, token_es}, // →
			messagePattern{token_e, token_ee}, // ←
			messagePattern{token_s, token_se}, // →
		},
	},
	/*
		IK(s, rs):
		<- s
		...
		-> e, es, s, ss
		<- e, ee, se
	*/
	NoiseIK: handshakePattern{
		name: "IK",
		preMessagePatterns: []messagePattern{
			messagePattern{},        // →
			messagePattern{token_s}, // ←
		},
		messagePatterns: []messagePattern{
			messagePattern{token_e, token_es, token_s, token_ss}, // →
			messagePattern{token_e, token_ee, token_se},          // ←
		},
	},
	/*
		IX(s, rs):
		 -> e, s
		 <- e, ee, se, s, es
	*/
	NoiseIX: handshakePattern{
		name: "IX",
		preMessagePatterns: []messagePattern{
			messagePattern{}, // →
			messagePattern{}, // ←
		},
		messagePatterns: []messagePattern{
			messagePattern{token_e, token_s},                               // →
			messagePattern{token_e, token_ee, token_se, token_s, token_es}, // ←
		},
	},

	/*
		NNpsk2():
		  -> e
		  <- e, ee, psk
	*/
	NoiseNNpsk2: handshakePattern{
		name: "NNpsk2",
		preMessagePatterns: []messagePattern{
			messagePattern{}, // →
			messagePattern{}, // ←
		},
		messagePatterns: []messagePattern{
			messagePattern{token_e},                      // →
			messagePattern{token_e, token_ee, token_psk}, // ←
		},
	},
}
