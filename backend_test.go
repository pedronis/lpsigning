// -*- Mode: Go; indent-tabs-mode: t -*-

/*
 * Copyright (C) 2026 Canonical Ltd
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 3 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 */

package lpsigning

import (
	"bytes"
	"crypto"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/nacl/box"
	"golang.org/x/crypto/openpgp/armor"
	"golang.org/x/crypto/openpgp/packet"
	check "gopkg.in/check.v1"

	"github.com/snapcore/snapd/asserts"
	"github.com/snapcore/snapd/asserts/assertstest"
)

func Test(t *testing.T) { check.TestingT(t) }

type backendSuite struct{}

var _ = check.Suite(&backendSuite{})

type mockSigningService struct {
	servicePublicKey  *[32]byte
	servicePrivateKey *[32]byte
	lastSignRequest   lpSigningSignRequest
	armoredSignature  []byte
	signingKey        *rsa.PrivateKey
	responsePublicKey []byte
	errorMessage      string
	nonceValue        [24]byte
}

func newMockSigningService(c *check.C, armoredSignature []byte, responsePublicKey []byte) *mockSigningService {
	servicePublicKey, servicePrivateKey, err := generateX25519Keypair(rand.Reader)
	c.Assert(err, check.IsNil)
	service := &mockSigningService{
		servicePublicKey:  servicePublicKey,
		servicePrivateKey: servicePrivateKey,
		armoredSignature:  armoredSignature,
		responsePublicKey: responsePublicKey,
	}
	copy(service.nonceValue[:], []byte("0123456789abcdefghijklmn"))
	return service
}

func (s *mockSigningService) handler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/service-key":
			_ = json.NewEncoder(w).Encode(map[string]string{
				"service-key": base64.StdEncoding.EncodeToString(s.servicePublicKey[:]),
			})
		case "/nonce":
			w.WriteHeader(http.StatusCreated)
			_ = json.NewEncoder(w).Encode(map[string]string{
				"nonce": base64.StdEncoding.EncodeToString(s.nonceValue[:]),
			})
		case "/sign":
			s.handleSign(w, r)
		default:
			http.NotFound(w, r)
		}
	})
}

func (s *mockSigningService) handleSign(w http.ResponseWriter, r *http.Request) {
	clientPublicKey, requestNonce, responseNonce, ciphertext := decodeBoxedRequest(r)
	plaintext, ok := box.Open(nil, ciphertext, requestNonce, clientPublicKey, s.servicePrivateKey)
	if !ok {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	var request lpSigningSignRequest
	if err := json.Unmarshal(plaintext, &request); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	s.lastSignRequest = request

	status := http.StatusOK
	var responseBody []byte
	if s.errorMessage != "" {
		status = http.StatusBadRequest
		responseBody, _ = json.Marshal(map[string]any{
			"error_list": []map[string]string{{"message": s.errorMessage}},
		})
	} else {
		armoredSignature := s.armoredSignature
		if s.signingKey != nil {
			message, err := base64.StdEncoding.DecodeString(request.Message)
			if err != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			armoredSignature, _, err = makeArmoredDetachedSignatureBytes(s.signingKey, message)
			if err != nil {
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
		}
		responseBody, _ = json.Marshal(map[string]string{
			"signed-message": base64.StdEncoding.EncodeToString(armoredSignature),
			"public-key":     base64.StdEncoding.EncodeToString(s.responsePublicKey),
		})
	}

	boxed := box.Seal(nil, responseBody, responseNonce, clientPublicKey, s.servicePrivateKey)
	w.Header().Set("Content-Type", "application/x-boxed-json")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(base64.StdEncoding.EncodeToString(boxed)))
}

func decodeBoxedRequest(r *http.Request) (*[32]byte, *[24]byte, *[24]byte, []byte) {
	clientPublicKey := new([32]byte)
	decodedClientPublicKey, _ := base64.StdEncoding.DecodeString(r.Header.Get("X-Client-Public-Key"))
	copy(clientPublicKey[:], decodedClientPublicKey)

	requestNonce := new([24]byte)
	decodedRequestNonce, _ := base64.StdEncoding.DecodeString(r.Header.Get("X-Nonce"))
	copy(requestNonce[:], decodedRequestNonce)

	responseNonce := new([24]byte)
	decodedResponseNonce, _ := base64.StdEncoding.DecodeString(r.Header.Get("X-Response-Nonce"))
	copy(responseNonce[:], decodedResponseNonce)

	body, _ := io.ReadAll(r.Body)
	decodedBody, _ := base64.StdEncoding.DecodeString(string(body))

	return clientPublicKey, requestNonce, responseNonce, decodedBody
}

func makeArmoredDetachedSignature(c *check.C, privateKey *rsa.PrivateKey, content []byte) ([]byte, []byte) {
	armored, raw, err := makeArmoredDetachedSignatureBytes(privateKey, content)
	c.Assert(err, check.IsNil)
	return armored, raw
}

func makeArmoredDetachedSignatureBytes(privateKey *rsa.PrivateKey, content []byte) ([]byte, []byte, error) {
	sig := new(packet.Signature)
	sig.PubKeyAlgo = packet.PubKeyAlgoRSA
	sig.Hash = crypto.SHA512
	sig.CreationTime = time.Now()

	h := crypto.SHA512.New()
	h.Write(content)
	err := sig.Sign(h, packet.NewRSAPrivateKey(time.Unix(1, 0), privateKey), &packet.Config{DefaultHash: crypto.SHA512})
	if err != nil {
		return nil, nil, err
	}

	raw := bytes.NewBuffer(nil)
	if err := sig.Serialize(raw); err != nil {
		return nil, nil, err
	}

	armored := bytes.NewBuffer(nil)
	armorWriter, err := armor.Encode(armored, "PGP SIGNATURE", nil)
	if err != nil {
		return nil, nil, err
	}
	if err := sig.Serialize(armorWriter); err != nil {
		return nil, nil, err
	}
	if err := armorWriter.Close(); err != nil {
		return nil, nil, err
	}

	return armored.Bytes(), raw.Bytes(), nil
}

func makeAccountKey(c *check.C, pubKey asserts.PublicKey) *asserts.AccountKey {
	store := assertstest.NewStoreStack("trusted", nil)
	brandAcct := assertstest.NewAccount(store, "brand", map[string]any{
		"account-id": "brand-id",
	}, "")
	return assertstest.NewAccountKey(store, brandAcct, nil, pubKey, "")
}

func generateX25519Keypair(random io.Reader) (*[32]byte, *[32]byte, error) {
	curve := ecdh.X25519()
	priv, err := curve.GenerateKey(random)
	if err != nil {
		return nil, nil, err
	}
	privateKey := new([32]byte)
	copy(privateKey[:], priv.Bytes())
	publicKey := new([32]byte)
	copy(publicKey[:], priv.PublicKey().Bytes())
	return publicKey, privateKey, nil
}

func (s *backendSuite) TestConstructorRejectsMissingAccountKey(c *check.C) {
	_, clientPrivateKey, err := generateX25519Keypair(rand.Reader)
	c.Assert(err, check.IsNil)

	_, err = NewKeypairMgrBackend(Config{
		BaseURL:          "http://example.com",
		ClientPrivateKey: base64.StdEncoding.EncodeToString(clientPrivateKey[:]),
		Keys: []KeyConfig{{
			AccountKey:  nil,
			Fingerprint: "FINGERPRINT",
		}},
	})
	c.Assert(err, check.ErrorMatches, `cannot create lp-signing backend: missing account-key assertion`)
}

func (s *backendSuite) TestSignDearmorsDetachedSignature(c *check.C) {
	privKey, rsaPrivKey := assertstest.ReadPrivKey(assertstest.DevKey)
	accountKey := makeAccountKey(c, privKey.PublicKey())
	armored, raw := makeArmoredDetachedSignature(c, rsaPrivKey, []byte("content to sign"))
	service := newMockSigningService(c, armored, accountKey.Body())
	server := httptest.NewServer(service.handler())
	defer server.Close()

	_, clientPrivateKey, err := generateX25519Keypair(rand.Reader)
	c.Assert(err, check.IsNil)

	backend, err := NewKeypairMgrBackend(Config{
		BaseURL:          server.URL,
		ClientPrivateKey: base64.StdEncoding.EncodeToString(clientPrivateKey[:]),
		Keys: []KeyConfig{{
			AccountKey:  accountKey,
			Fingerprint: "LPFPR1",
		}},
	})
	c.Assert(err, check.IsNil)

	loaded, err := backend.LoadByID(accountKey.PublicKeyID())
	c.Assert(err, check.IsNil)
	signed, err := backend.Sign(loaded.KeyHandle, []byte("content to sign"))
	c.Assert(err, check.IsNil)

	c.Check(signed, check.DeepEquals, raw)
	c.Check(service.lastSignRequest.KeyType, check.Equals, lpSigningKeyTypeOpenPGP)
	c.Check(service.lastSignRequest.Fingerprint, check.Equals, "LPFPR1")
	c.Check(service.lastSignRequest.Mode, check.Equals, lpSigningModeDetached)
	decodedMessage, err := base64.StdEncoding.DecodeString(service.lastSignRequest.Message)
	c.Assert(err, check.IsNil)
	c.Check(decodedMessage, check.DeepEquals, []byte("content to sign"))
	_, err = packet.Read(bytes.NewReader(signed))
	c.Assert(err, check.IsNil)
}

func (s *backendSuite) TestExternalKeypairManagerIntegration(c *check.C) {
	privKey, rsaPrivKey := assertstest.ReadPrivKey(assertstest.DevKey)
	accountKey := makeAccountKey(c, privKey.PublicKey())
	service := newMockSigningService(c, nil, accountKey.Body())
	service.signingKey = rsaPrivKey
	server := httptest.NewServer(service.handler())
	defer server.Close()

	_, clientPrivateKey, err := generateX25519Keypair(rand.Reader)
	c.Assert(err, check.IsNil)

	backend, err := NewKeypairMgrBackend(Config{
		BaseURL:          server.URL,
		ClientPrivateKey: base64.StdEncoding.EncodeToString(clientPrivateKey[:]),
		Keys: []KeyConfig{{
			AccountKey:  accountKey,
			Fingerprint: "LPFPR2",
		}},
	})
	c.Assert(err, check.IsNil)

	kmgr, err := asserts.NewExternalKeypairManagerWithBackend(backend, asserts.ExtKeypairMgrConfig{
		SigningWith: "lp-signing",
		KeyStore:    "lp-signing",
	})
	c.Assert(err, check.IsNil)

	pk, err := kmgr.Get(accountKey.PublicKeyID())
	c.Assert(err, check.IsNil)
	c.Check(pk.PublicKey().ID(), check.Equals, accountKey.PublicKeyID())

	store := assertstest.NewStoreStack("trusted", nil)
	brandAcct := assertstest.NewAccount(store, "brand", map[string]any{
		"account-id": "brand-id",
	}, "")
	brandAccKey := assertstest.NewAccountKey(store, brandAcct, nil, pk.PublicKey(), "")

	signDB, err := asserts.OpenDatabase(&asserts.DatabaseConfig{KeypairManager: kmgr})
	c.Assert(err, check.IsNil)
	checkDB, err := asserts.OpenDatabase(&asserts.DatabaseConfig{
		Backstore: asserts.NewMemoryBackstore(),
		Trusted:   store.Trusted,
	})
	c.Assert(err, check.IsNil)
	err = checkDB.Add(store.StoreAccountKey(""))
	c.Assert(err, check.IsNil)
	err = checkDB.Add(brandAcct)
	c.Assert(err, check.IsNil)
	err = checkDB.Add(brandAccKey)
	c.Assert(err, check.IsNil)

	modelHeaders := map[string]any{
		"authority-id": "brand-id",
		"brand-id":     "brand-id",
		"model":        "model",
		"series":       "16",
		"architecture": "amd64",
		"base":         "core18",
		"gadget":       "gadget",
		"kernel":       "pc-kernel",
		"timestamp":    time.Now().Format(time.RFC3339),
	}
	a, err := signDB.Sign(asserts.ModelType, modelHeaders, nil, pk.PublicKey().ID())
	c.Assert(err, check.IsNil)
	err = checkDB.Check(a)
	c.Assert(err, check.IsNil)

	_, err = kmgr.GetByName("default")
	c.Assert(err, check.ErrorMatches, `cannot get key by name from sign-only external keypair manager`)
	_, err = kmgr.Export("default")
	c.Assert(err, check.ErrorMatches, `cannot get key by name from sign-only external keypair manager`)
	_, err = kmgr.List()
	c.Assert(err, check.ErrorMatches, `cannot list keys in sign-only external keypair manager`)
	c.Check(service.lastSignRequest.Fingerprint, check.Equals, "LPFPR2")
	c.Check(strings.TrimSpace(service.lastSignRequest.MessageName), check.Not(check.Equals), "")
}
