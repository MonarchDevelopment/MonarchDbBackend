package security

import (
	"monarch/backend/config"
	"errors"
	"github.com/golang-jwt/jwt"
	"log"
	"strings"
	"time"
)

const AUTH_HEADER = "Authorization"

/*has subject, type and, expires. See the api docs for help.*/
type Claims struct {
	Type       string `json:"type"`
	UserType   string `json:"user_type"`
	Uuid       string `json:"uuid"`
	IssueDate  int64  `json:"issue_date"`
	ExpiryDate int64  `json:"expiry_date"`
	Firstname  string `json:"firstname"`
	Surname    string `json:"surname"`
}

func (c Claims) Valid() error {
	valid := c.Type != "" && c.UserType != "" && c.Uuid != "" && c.Firstname != "" && c.Surname != ""
	if !valid {
		return errors.New("Bad claims")
	}

	return nil
}

func CheckHeaderJwt(JwtIn string, conf config.Config) (Claims, error) {
	splitJwt := strings.Split(JwtIn, "Bearer ")
	if len(splitJwt) < 2 {
		return Claims{}, errors.New("No Bearer token found")
	}
	return CheckJwt(splitJwt[1], conf)
}

func __CheckJwt(JwtIn string, conf config.Config) (Claims, error) {
	ret := Claims{}

	_, err := jwt.ParseWithClaims(
		JwtIn,
		&ret,
		func(token *jwt.Token) (interface{}, error) {
			return []byte(conf.JwtSecret), nil
		},
	)

	if err != nil {
		log.Printf("An error %s occurred when checking %s\n", err, JwtIn)
		return Claims{}, err
	}

	if ret.ExpiryDate <= time.Now().Unix() {
		log.Println(ret)
		log.Println("The jwt is expired")
		return Claims{}, errors.New("The jwt is expired")
	}

	return ret, nil
}

func CheckIcalJwt(JwtIn string, conf config.Config) (Claims, error) {
	ret, err := __CheckJwt(JwtIn, conf)
	if err != nil {
		return Claims{}, errors.New("Invalid JWT")
	}

	if ret.Type != "ICAL" {
		log.Println("The jwt is not an ical token, this is forbidden")
		return Claims{}, errors.New("The jwt is not an ical token. This is forbidden")
	}
	return ret, nil
}

func CheckJwt(JwtIn string, conf config.Config) (Claims, error) {
	ret, err := __CheckJwt(JwtIn, conf)
	if err != nil {
		return Claims{}, errors.New("Invalid JWT")
	}

	if ret.Type != "ACCESS" {
		log.Println("The jwt is not an access token, this is forbidden")
		return Claims{}, errors.New("The jwt is not an access token. This is forbidden")
	}
	return ret, nil
}
