package main

import (
	"monarch/backend/config"
	"monarch/backend/security"
	"monarch/backend/utils"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"
)

var GlobalConfig config.Config
var DatabasePool *utils.DatabasePool
var NonceManager security.NonceManager

const MAX_BODY = 1024 * 1024

func statusHandler(w http.ResponseWriter, r *http.Request) {
	fmt.Fprintln(w, "online")
}

func checkAuthentication(_ security.Claims, w http.ResponseWriter, _ *http.Request) {
	SendSuccess(w)
}

type ErrorMessage struct {
	Error string `json:"error"`
}

func SendError(w http.ResponseWriter, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusBadRequest)
	jsonmsg := ErrorMessage{Error: msg}
	jsonout, err := json.Marshal(jsonmsg)
	if err != nil {
		log.Println(err)
		fmt.Fprintln(w, "{\"error\":\"cannot show error\"}")
		return
	}

	fmt.Fprintln(w, string(jsonout))
}

func SendSuccess(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	fmt.Fprintln(w, "{\"success\":true}")
}

func main() {
	log.SetFlags(log.Llongfile | log.Ldate | log.Ltime | log.Lmicroseconds)
	log.Println("Starting the monarch backend server")

	// Read configuration and connect to the database
	conf := config.LoadConfig()
	database, err := utils.InitDatabasePool(conf)
	if err != nil {
		log.Fatalf("Cannot initialise connection to the database - %s\n", err)
	}

	// Setup the nonce manager
	log.Println("Starting nonce manager")
	NonceManager.InitNonceManager()
	http.HandleFunc("/get-nonce", CheckPreflight(func(w http.ResponseWriter, r *http.Request) {
		nonce, err := NonceManager.GetNonce()
		if err != nil {
			SendError(w, INTERNAL_ERROR)
			return
		}

		//Convert them into strings as JS doesn't like large numbers
		stringNonce := strconv.FormatInt(nonce, 10)
		fmt.Fprintf(w, "{\"nonce\":\"%s\"}", stringNonce)
	}))

	// Setup and start the server
	log.Println("Adding debug endpoints")
	http.HandleFunc("/status", CheckPreflight(statusHandler))
	http.HandleFunc("/check-auth", CheckAuth(checkAuthentication))

	// Finish setup
	GlobalConfig = conf
	DatabasePool = database

	bindAddr := fmt.Sprintf("%s:%d", conf.BindAddr, conf.BindPort)
	log.Printf("Started the monarch backend server on http://%s\n", bindAddr)

	log.Fatal(http.ListenAndServe(bindAddr, nil))
}
