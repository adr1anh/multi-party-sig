package params

import "github.com/decred/dcrd/dcrec/secp256k1/v3"

const (
	SecParam  = 256
	HashBytes = 64
	SecBytes  = 32
	StatParam = 80

	// ZKModIterations is the number of iterations that are performed to prove the validity of
	// a Paillier-Blum modulus N.
	// Theoretically, the number of iterations corresponds to the statistical security parameter,
	// and would be 80.
	// The way it is used in the refresh protocol ensures that the prover cannot guess in advance the secret ρ
	// used to instantiate the hash function.
	// Since sampling primes is expensive, we argue that the security can be reduced.
	ZKModIterations = 12

	L                 = 1 * SecParam     // = 256
	LPrime            = 5 * SecParam     // = 1280
	Epsilon           = 2 * SecParam     // = 512
	LPlusEpsilon      = L + Epsilon      // = 768
	LPrimePlusEpsilon = LPrime + Epsilon // 1792

	BitsIntModN  = 8 * SecParam    // = 2048
	BytesIntModN = BitsIntModN / 8 // = 256

	BitsBlumPrime = 4 * SecParam      // = 1024
	BitsPaillier  = 2 * BitsBlumPrime // = 2048

	BytesPaillier   = BitsPaillier / 8  // = 256
	BytesCiphertext = 2 * BytesPaillier // = 512

	BytesPoint  = secp256k1.PubKeyBytesLenCompressed
	BytesScalar = 32
)