package main

import (
	"net/http"

	"github.com/arjunmalhotra1/application-UserLogin/authenticator"
	"github.com/arjunmalhotra1/application-UserLogin/db/mysql"
)

func main() {
	mySqlDb := mysql.New()
	dba := authenticator.NewAuthenticator(mySqlDb)

	// TODO Make this TLS
	http.HandleFunc("/user-sign-up", dba.UserSignUp)
	http.HandleFunc("/user-login", dba.UserLogin)
	http.HandleFunc("/user-logout", dba.UserLogout)
	http.ListenAndServe(":8086", nil)
}
