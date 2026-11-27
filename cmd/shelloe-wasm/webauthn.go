//go:build js && wasm

package main

import (
	"context"
	"errors"
	"fmt"
	"syscall/js"

	"github.com/loemraw/shelloe/internal/securitykey"
)

var errSessionEnded = errors.New("the session ended")

// webAuthn returns an Authenticator that asks the security key through the
// browser's navigator.credentials.get, and gives up when ctx ends.
func webAuthn(ctx context.Context) securitykey.Authenticator {
	return func(rpID string, challenge []byte) (*securitykey.Assertion, error) {
		if ctx.Err() != nil {
			return nil, errSessionEnded
		}
		challengeArray := uint8Array.New(len(challenge))
		js.CopyBytesToJS(challengeArray, challenge)
		controller := js.Global().Get("AbortController").New()
		options := map[string]any{
			"publicKey": map[string]any{
				"challenge": challengeArray,
				"rpId":      rpID,
				// The credential is discoverable: the security key finds it by the site.
				"allowCredentials": []any{},
				"userVerification": "required",
			},
			"signal": controller.Get("signal"),
		}

		type result struct {
			assertion *securitykey.Assertion
			err       error
		}
		settled := make(chan result, 1)
		fulfilled := js.FuncOf(func(_ js.Value, args []js.Value) any {
			response := args[0].Get("response")
			settled <- result{assertion: &securitykey.Assertion{
				AuthenticatorData: bytesOf(response.Get("authenticatorData")),
				ClientDataJSON:    bytesOf(response.Get("clientDataJSON")),
				Signature:         bytesOf(response.Get("signature")),
			}}
			return nil
		})
		rejected := js.FuncOf(func(_ js.Value, args []js.Value) any {
			settled <- result{err: fmt.Errorf("%s: %s", args[0].Get("name").String(), args[0].Get("message").String())}
			return nil
		})
		// Unlike the session's Funcs, these can be released: the promise calls one of them, once, as it settles.
		defer fulfilled.Release()
		defer rejected.Release()
		js.Global().Get("navigator").Get("credentials").Call("get", options).Call("then", fulfilled, rejected)

		select {
		case r := <-settled:
			return r.assertion, r.err
		case <-ctx.Done():
			controller.Call("abort")
			<-settled
			return nil, errSessionEnded
		}
	}
}

// bytesOf copies an ArrayBuffer's bytes.
func bytesOf(buffer js.Value) []byte {
	view := uint8Array.New(buffer)
	b := make([]byte, view.Length())
	js.CopyBytesToGo(b, view)
	return b
}
