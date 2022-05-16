package main

import (
	"monarch/backend/security"
	"fmt"
	"net/http"
	"strconv"
)

type MiddlewareFn func(http.ResponseWriter, *http.Request)
type AuthorisedFn func(security.Claims, http.ResponseWriter, *http.Request)

func CheckPreflight(req MiddlewareFn) MiddlewareFn {
	return func(w http.ResponseWriter, r *http.Request) {
		//Set some default headers
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Headers", "*")

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			fmt.Fprintf(w, "")
			return
		}

		req(w, r)
	}
}

const ICAL_AUTH_HEADER = "ical-auth"
const AUTH_HEADER = "Authorization"
const NOT_AUTHORISED = "Not authorised"
const NONCE_HEADER = "Nonce"
const NONCE_INVALID = "nonce is invalid"
const INTERNAL_ERROR = "internal server error"

/*
* Middleware to check authentication and set basic headers,
 */
func CheckAuth(req AuthorisedFn) MiddlewareFn {
	return CheckPreflight(func(w http.ResponseWriter, r *http.Request) {
		nonce, err := strconv.ParseInt(r.Header.Get(NONCE_HEADER), 10, 64)
		if err != nil {
			SendError(w, NONCE_INVALID)
			return
		}

		err = NonceManager.UseNonce(nonce)
		if err != nil {
			SendError(w, NONCE_INVALID)
			return
		}

		token := r.Header.Get(AUTH_HEADER)
		claims, err := security.CheckHeaderJwt(token, GlobalConfig)
		if err != nil {
			SendError(w, NOT_AUTHORISED)
			return
		}

		req(claims, w, r)
	})
}
