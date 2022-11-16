package main

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"os"

	"github.com/flynn/go-docopt"
	tuf "github.com/theupdateframework/go-tuf"
	tufdata "github.com/theupdateframework/go-tuf/data"
	tufkeys "github.com/theupdateframework/go-tuf/pkg/keys"
	tufsign "github.com/theupdateframework/go-tuf/sign"
)

func init() {
	register("sign-payload", cmdSignPayload, `
usage: tuf sign-payload [--role=<role>] [--key=<key>] <path>

Sign a file outside of the TUF repo. If a key is explicitly specified, it is
used. Otherwise, the keys for the given role from the TUF repo are used. One of
--role and --key must be set.

Typically, path will be the output of "tuf payload".
`)
}

func cmdSignPayload(args *docopt.Args, repo *tuf.Repo) error {
	if args.String["--role"] == "" && args.String["--key"] == "" {
		return fmt.Errorf("tuf: both --role and --key cannot be empty")
	}

	payload, err := os.ReadFile(args.String["<path>"])
	if err != nil {
		return err
	}

	signed := tufdata.Signed{Signed: payload, Signatures: make([]tufdata.Signature, 0)}
	var numKeys int

	if keyPath, ok := args.String["--key"]; ok {
		fmt.Fprintln(os.Stderr, "tuf: using", keyPath, "to sign metadata")
		key, err := loadEd25519PrivateKeyFromSslib(keyPath)
		if err != nil {
			return err
		}

		numKeys = 1
		signer, err := tufkeys.GetSigner(&key)
		if err != nil {
			return err
		}

		tufsign.Sign(&signed, signer)
	} else {
		numKeys, err = repo.SignPayload(args.String["--role"], &signed)
		if err != nil {
			return err
		}
	}

	bytes, err := json.Marshal(signed.Signatures)
	if err != nil {
		return err
	}
	fmt.Fprint(os.Stdout, string(bytes))

	fmt.Fprintln(os.Stderr, "tuf: signed with", numKeys, "key(s)")
	return nil
}

func loadEd25519PrivateKeyFromSslib(path string) (tufdata.PrivateKey, error) {
	var privKey tufdata.PrivateKey
	privKeyData, err := os.ReadFile(path)
	if err != nil {
		return tufdata.PrivateKey{}, err
	}
	err = json.Unmarshal(privKeyData, &privKey)
	if err != nil {
		return tufdata.PrivateKey{}, err
	}

	var kv keyValue
	err = json.Unmarshal(privKey.Value, &kv)
	if err != nil {
		return tufdata.PrivateKey{}, err
	}
	/*
		Here, the assumption is that the key pair is in the securesystemslib
		format. However, the default python-sslib format does not contain the
		private and the public halves of the key in the "private" field as
		go-tuf expects. So, while a keypair can be generated using python-sslib,
		the public portion must be appended to the private portion in the JSON
		representation.
	*/
	if len(kv.Private) < ed25519.PrivateKeySize {
		fullPrivateValue, err := json.Marshal(keyValue{
			Private: append(kv.Private, kv.Public...),
			Public:  kv.Public,
		})
		if err != nil {
			return tufdata.PrivateKey{}, err
		}
		return tufdata.PrivateKey{
			Type:       privKey.Type,
			Scheme:     privKey.Scheme,
			Algorithms: privKey.Algorithms,
			Value:      fullPrivateValue,
		}, nil
	}

	return privKey, nil
}

type keyValue struct {
	Private []byte `json:"private,omitempty"`
	Public  []byte `json:"public,omitempty"`
}
