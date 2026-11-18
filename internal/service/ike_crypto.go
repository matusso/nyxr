package service

import (
	"crypto"
	"crypto/aes"
	"crypto/cipher"
	"crypto/des" //nolint:gosec // 3DES is offered because legacy gateways still pick it
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1" //nolint:gosec // negotiated IKE PRF and integrity algorithm
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"math/big"
)

func hexInt(s string) *big.Int {
	n, ok := new(big.Int).SetString(s, 16)
	if !ok {
		panic("bad prime")
	}
	return n
}

// modpPrimes are the RFC 2409 and RFC 3526 MODP groups by IKE group number;
// the generator is 2.
var modpPrimes = map[uint16]*big.Int{
	2: hexInt("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DD" +
		"EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED" +
		"EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF"),
	14: hexInt("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DD" +
		"EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED" +
		"EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F" +
		"83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B" +
		"E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA0510" +
		"15728E5A8AACAA68FFFFFFFFFFFFFFFF"),
	15: hexInt("FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DD" +
		"EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED" +
		"EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F" +
		"83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B" +
		"E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA0510" +
		"15728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7" +
		"ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6BF12FFA06D98A0864D87602733EC86A64521F2B18177B200C" +
		"BBE117577A615D6C770988C0BAD946E208E24FA074E5AB3143DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF"),
}

// ikeDH is the initiator's half of a Diffie-Hellman exchange.
type ikeDH struct {
	group  uint16
	public []byte
	shared func(peer []byte) ([]byte, error)
}

func newIKEDH(group uint16) (*ikeDH, error) {
	if p := modpPrimes[group]; p != nil {
		secret := make([]byte, 32)
		if _, err := rand.Read(secret); err != nil {
			return nil, err
		}
		x, size := new(big.Int).SetBytes(secret), (p.BitLen()+7)/8
		return &ikeDH{group, new(big.Int).Exp(big.NewInt(2), x, p).FillBytes(make([]byte, size)), func(peer []byte) ([]byte, error) {
			y := new(big.Int).SetBytes(peer)
			if y.Cmp(big.NewInt(1)) <= 0 || y.Cmp(new(big.Int).Sub(p, big.NewInt(1))) >= 0 {
				return nil, errors.New("ike: invalid peer public value")
			}
			return y.Exp(y, x, p).FillBytes(make([]byte, size)), nil
		}}, nil
	}
	curve := map[uint16]ecdh.Curve{19: ecdh.P256(), 20: ecdh.P384(), 31: ecdh.X25519()}[group]
	if curve == nil {
		return nil, fmt.Errorf("ike: unsupported group %d", group)
	}
	key, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	// RFC 5903: ECP values travel as x|y, without the SEC1 0x04 prefix.
	public, point := key.PublicKey().Bytes(), group != 31
	if point {
		public = public[1:]
	}
	return &ikeDH{group, public, func(peer []byte) ([]byte, error) {
		if point {
			peer = append([]byte{4}, peer...)
		}
		pub, err := curve.NewPublicKey(peer)
		if err != nil {
			return nil, err
		}
		return key.ECDH(pub)
	}}, nil
}

var (
	ikev2PRFs   = map[uint16]func() hash.Hash{2: sha1.New, 5: sha256.New, 6: sha512.New384, 7: sha512.New}
	ikev2Integs = map[uint16]struct {
		hash func() hash.Hash
		icv  int
	}{2: {sha1.New, 12}, 12: {sha256.New, 16}, 13: {sha512.New384, 24}, 14: {sha512.New, 32}}
)

// ikev2Keys protect IKE SA messages: CBC encryption and a truncated HMAC.
// prf and pr (SK_pr) are what the responder's AUTH payload is computed with.
type ikev2Keys struct {
	block              func(key []byte) (cipher.Block, error)
	integ, prf         func() hash.Hash
	icv                int
	ai, ar, ei, er, pr []byte
}

func hmacSum(h func() hash.Hash, key []byte, data ...[]byte) []byte {
	mac := hmac.New(h, key)
	for _, d := range data {
		mac.Write(d)
	}
	return mac.Sum(nil)
}

// ikev2Derive computes the SK_a, SK_e and SK_pr keys of RFC 7296 2.14 for the picked
// transforms ({id, key bits} by transform type). spis is SPIi | SPIr.
func ikev2Derive(picked map[byte][2]uint16, shared, ni, nr, spis []byte) (*ikev2Keys, error) {
	prf, integ := ikev2PRFs[picked[2][0]], ikev2Integs[picked[3][0]]
	k := &ikev2Keys{integ: integ.hash, prf: prf, icv: integ.icv}
	encLen := 0
	switch picked[1][0] {
	case 12:
		k.block, encLen = aes.NewCipher, int(picked[1][1])/8
	case 3:
		k.block, encLen = des.NewTripleDESCipher, 24
	}
	if prf == nil || integ.hash == nil || (encLen != 16 && encLen != 24 && encLen != 32) {
		return nil, errors.New("ike: unsupported transforms")
	}
	skeyseed := hmacSum(prf, append(append([]byte(nil), ni...), nr...), shared)
	// prf+: T1 = prf(K, S | 1), Tn = prf(K, Tn-1 | S | n). The stream is
	// SK_d | SK_ai | SK_ar | SK_ei | SK_er | SK_pi | SK_pr.
	seed := append(append(append([]byte(nil), ni...), nr...), spis...)
	prfLen, aLen := prf().Size(), integ.hash().Size()
	var stream, t []byte
	for n := byte(1); len(stream) < 3*prfLen+2*aLen+2*encLen; n++ {
		t = hmacSum(prf, skeyseed, t, seed, []byte{n})
		stream = append(stream, t...)
	}
	stream = stream[prfLen:]
	k.ai, k.ar, stream = stream[:aLen], stream[aLen:2*aLen], stream[2*aLen:]
	k.ei, k.er, k.pr = stream[:encLen], stream[encLen:2*encLen], stream[2*encLen+prfLen:2*encLen+2*prfLen]
	return k, nil
}

// seal builds a message whose payloads (inner, starting with a payload of
// type first) travel in an Encrypted payload (RFC 7296 3.14), protected with
// the initiator's keys. frag, when given, is the {number, total} of an
// RFC 7383 Encrypted Fragment payload instead.
func (k *ikev2Keys) seal(spis []byte, exchange, flags byte, messageID uint32, first byte, inner []byte, frag ...uint16) ([]byte, error) {
	block, err := k.block(k.ei)
	if err != nil {
		return nil, err
	}
	bs := block.BlockSize()
	pad := (bs - (len(inner)+1)%bs) % bs
	plain := append(append(append([]byte(nil), inner...), make([]byte, pad)...), byte(pad))
	iv := make([]byte, bs)
	if _, err := rand.Read(iv); err != nil {
		return nil, err
	}
	cipher.NewCBCEncrypter(block, iv).CryptBlocks(plain, plain)
	msg := append(append([]byte(nil), spis...), 46, 0x20, exchange, flags, 0, 0, 0, 0, 0, 0, 0, 0, first, 0, 0, 0)
	if len(frag) == 2 {
		msg[16] = 53
		msg = append(msg, byte(frag[0]>>8), byte(frag[0]), byte(frag[1]>>8), byte(frag[1]))
	}
	msg = append(append(msg, iv...), plain...)
	binary.BigEndian.PutUint32(msg[20:24], messageID)
	binary.BigEndian.PutUint32(msg[24:28], uint32(len(msg)+k.icv))
	binary.BigEndian.PutUint16(msg[30:32], uint16(len(msg)+k.icv-28))
	return append(msg, hmacSum(k.integ, k.ai, msg)[:k.icv]...), nil
}

// decrypt verifies a responder message that consists of one Encrypted or
// Encrypted Fragment payload and returns its plaintext with the fragment's
// number and total (both 1 when unfragmented).
func (k *ikev2Keys) decrypt(msg []byte) (plain []byte, num, total int, err error) {
	block, err := k.block(k.er)
	if err != nil {
		return nil, 0, 0, err
	}
	bs, start := block.BlockSize(), 32
	num, total = 1, 1
	if len(msg) >= 36 && msg[16] == 53 {
		start, num, total = 36, int(binary.BigEndian.Uint16(msg[32:34])), int(binary.BigEndian.Uint16(msg[34:36]))
	}
	if len(msg) < start+2*bs+k.icv || (msg[16] != 46 && msg[16] != 53) || num < 1 || num > total ||
		28+int(binary.BigEndian.Uint16(msg[30:32])) != len(msg) {
		return nil, 0, 0, errors.New("ike: not a single encrypted payload")
	}
	signed, body := msg[:len(msg)-k.icv], msg[start:len(msg)-k.icv]
	if len(body)%bs != 0 || !hmac.Equal(hmacSum(k.integ, k.ar, signed)[:k.icv], msg[len(signed):]) {
		return nil, 0, 0, errors.New("ike: integrity check failed")
	}
	plain = make([]byte, len(body)-bs)
	cipher.NewCBCDecrypter(block, body[:bs]).CryptBlocks(plain, body[bs:])
	pad := int(plain[len(plain)-1])
	if pad+1 > len(plain) {
		return nil, 0, 0, errors.New("ike: bad padding")
	}
	return plain[:len(plain)-1-pad], num, total, nil
}

// ikePlain is the plaintext message decodeIKE can walk: header, then the
// decrypted payloads, the first of which has type first.
func ikePlain(header []byte, first byte, parts ...[]byte) []byte {
	out := append([]byte(nil), header[:28]...)
	for _, part := range parts {
		out = append(out, part...)
	}
	out[16] = first
	binary.BigEndian.PutUint32(out[24:28], uint32(len(out)))
	return out
}

// open decrypts an unfragmented responder message into its plaintext form.
func (k *ikev2Keys) open(msg []byte) ([]byte, error) {
	plain, _, total, err := k.decrypt(msg)
	if err != nil || total != 1 {
		return nil, errors.Join(err, errors.New("ike: cannot open message"))
	}
	return ikePlain(msg, msg[28], plain), nil
}

// ikev2VerifyAuth checks the responder's AUTH payload (RFC 7296 2.15) over
// signed against the certificate it sent. "verified" proves the gateway holds
// that certificate's private key; the chain is not validated.
func ikev2VerifyAuth(cert *x509.Certificate, method byte, signature, signed []byte) string {
	digest := func(h crypto.Hash) []byte {
		d := h.New()
		d.Write(signed)
		return d.Sum(nil)
	}
	switch pub := cert.PublicKey.(type) {
	case *rsa.PublicKey:
		if method != 1 {
			break
		}
		// RFC 7296 means SHA-1 here; some implementations sign with SHA-2
		// under the same method number.
		for _, h := range []crypto.Hash{crypto.SHA1, crypto.SHA256, crypto.SHA384, crypto.SHA512} {
			if rsa.VerifyPKCS1v15(pub, h, digest(h), signature) == nil {
				return "verified"
			}
		}
		return "invalid"
	case *ecdsa.PublicKey:
		// RFC 4754: the signature is r | s, the hash follows the method.
		h, half := map[byte]crypto.Hash{9: crypto.SHA256, 10: crypto.SHA384, 11: crypto.SHA512}[method], len(signature)/2
		if h == 0 || half == 0 {
			break
		}
		if ecdsa.Verify(pub, digest(h), new(big.Int).SetBytes(signature[:half]), new(big.Int).SetBytes(signature[half:])) {
			return "verified"
		}
		return "invalid"
	}
	// shortcut: RFC 7427 digital signatures (method 14) are not requested, so
	// they are not parsed; add them together with SIGNATURE_HASH_ALGORITHMS.
	return "not checked"
}
