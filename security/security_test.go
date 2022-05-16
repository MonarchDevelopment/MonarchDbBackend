package security

import (
	"monarch/backend/config"
	"github.com/golang-jwt/jwt"
	"testing"
	"time"
)

func TestCheckJwt(t *testing.T) {
	conf := config.Config{JwtSecret: "GoodSecret"}

	// Create a test JWT
	// HS512 is the standard we use.
	claims := Claims{Uuid: "i am a user id, I promise you",
		Type:       "ACCESS",
		UserType:   "STAFF",
		Firstname:  "Dave",
		Surname:    "Dave",
		IssueDate:  time.Now().Unix(),
		ExpiryDate: time.Now().Unix() + 9999}
	token := jwt.NewWithClaims(jwt.SigningMethodHS512, claims)
	signedToken, err := token.SignedString([]byte(conf.JwtSecret))

	signedToken = "Bearer " + signedToken

	if err != nil {
		t.Log("Cannot sign jwt")
		t.Fail()
	}

	_, err = CheckHeaderJwt(signedToken, conf)
	if err != nil {
		t.Log("Cannot verify known good jwt")
		t.Fail()
	}
}
