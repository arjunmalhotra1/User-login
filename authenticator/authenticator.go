package authenticator

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/mail"

	"github.com/go-chi/render"
	uuid "github.com/satori/go.uuid"
	"golang.org/x/crypto/bcrypt"
)

type User struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type dbAccessor interface {
	IsUserSignedUp(string) (error, bool)
	InsertSignedUpUser(User) error
	InsertLoggedInUser(string, string) error
	GetEncryptedPass(string) (string, error)
	GetCookie(string) (string, error)
	DeleteCookie(string) bool
}

type Authenticator struct {
	db dbAccessor
}

func NewAuthenticator(db dbAccessor) Authenticator {
	return Authenticator{
		db: db,
	}
}

// UserSignUp is used to sign-up a user. It first validates email. Then checks if the user
// is already signed up or not.
func (dba Authenticator) UserSignUp(res http.ResponseWriter, req *http.Request) {
	var tempUser User
	err := json.NewDecoder(req.Body).Decode(&tempUser)
	if err != nil {
		log.Printf("In user sign up error for user while decoding json %s %v", tempUser.Email, err)
		render.Status(req, http.StatusInternalServerError)
		render.JSON(res, req, "Internal server Error")
		return
	}
	if tempUser.Email == "" {
		log.Printf("In user sign up, no email provided.")
		render.Status(req, http.StatusBadRequest)
		render.JSON(res, req, "Email cannot be blank.")
		return
	}
	if tempUser.Password == "" {
		log.Printf("In user sign up, no password provided.")
		render.Status(req, http.StatusBadRequest)
		render.JSON(res, req, "Password cannot be blank.")
		return
	}
	_, err = mail.ParseAddress(tempUser.Email)
	if err != nil {
		log.Printf("In user sign up, invalid email provided.")
		render.Status(req, http.StatusBadRequest)
		render.JSON(res, req, "Please provide a valid email.")
		return
	}

	if ok, _ := dba.AlreadyLoggedIn(tempUser.Email, req); ok {
		log.Printf("In userSignUp User %s is already Logged in", tempUser.Email)
		render.JSON(res, req, "You are already signed up & Logged in.")
		return
	}
	err, ok := dba.db.IsUserSignedUp(tempUser.Email)
	if err != nil {
		log.Printf("In sign-up error for user: %s err: %v", tempUser.Email, err)
		render.Status(req, http.StatusInternalServerError)
		render.JSON(res, req, "Internal server Error")
		return
	}
	if ok {
		log.Printf("In userSignUp User %s is already signed up", tempUser.Email)
		render.JSON(res, req, "You are already signed up. Please log in.")
		return
	}

	encryptedPasswordBytes, err := HashPassword(tempUser.Password)
	if err != nil {
		log.Printf("In sign-up error for user while hashing password %s %v", tempUser.Email, err)
		render.Status(req, http.StatusInternalServerError)
		render.JSON(res, req, "Internal server Error")
		return
	}
	log.Printf("user registered %s", tempUser.Email)
	encryptedPasswordString := string(encryptedPasswordBytes)
	tempUser.Password = encryptedPasswordString
	err = dba.db.InsertSignedUpUser(tempUser)
	if err != nil {
		log.Printf("sign-up error for user: %s error: %v", tempUser.Email, err)
		render.Status(req, http.StatusInternalServerError)
		render.JSON(res, req, "Internal server Error")
		return
	}
	render.JSON(res, req, tempUser)
}

// HashPassword generates an encrypted password for a password sent by a user.
// Uses bcrypt library.
func HashPassword(password string) ([]byte, error) {
	bs, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return nil, fmt.Errorf("error while generating bcrypt hash from password: %w", err)
	}
	return bs, nil

}

// ComparePassword compares the encrypted password using the bcrypt library.
func ComparePassword(password string, hashedPass []byte) error {
	err := bcrypt.CompareHashAndPassword(hashedPass, []byte(password))
	if err != nil {
		return fmt.Errorf("error while comparing bcrypt hash with password: %v", err)
	}
	return nil

}

// UserLogin checks if a user is logged in or not and then sets a cookie in the client
// the cookie is used to determine if a user is logged in or not.
func (dba Authenticator) UserLogin(res http.ResponseWriter, req *http.Request) {
	var tempUser User
	err := json.NewDecoder(req.Body).Decode(&tempUser)
	if err != nil {
		log.Printf("In user login error for user while decoding %s %v", tempUser.Email, err)
		render.Status(req, http.StatusInternalServerError)
		render.JSON(res, req, "Internal server Error")
		return
	}
	if tempUser.Email == "" {
		log.Printf("In user sign up, no email provided.")
		render.Status(req, http.StatusBadRequest)
		render.JSON(res, req, "Email cannot be blank.")
		return
	}
	if tempUser.Password == "" {
		log.Printf("In user sign up, no password provided.")
		render.Status(req, http.StatusBadRequest)
		render.JSON(res, req, "Password cannot be blank.")
		return
	}
	err, isSignedUp := dba.db.IsUserSignedUp(tempUser.Email)
	if err != nil {
		log.Printf("In user login error for user: %s err: %v", tempUser.Email, err)
		render.Status(req, http.StatusInternalServerError)
		render.JSON(res, req, "Internal server Error")
		return
	}
	if isSignedUp {
		isLoggedIn, err := dba.AlreadyLoggedIn(tempUser.Email, req)
		if err != nil {
			log.Println(err)
			render.Status(req, http.StatusInternalServerError)
			render.JSON(res, req, "Internal server Error")
			return
		}
		if isLoggedIn {
			log.Printf("In user log in, user was already logged in, cookie already present")
			render.JSON(res, req, "You are logged in!")
			return
		}
		hashedPassword, _ := dba.db.GetEncryptedPass(tempUser.Email)
		err = ComparePassword(tempUser.Password, []byte(hashedPassword))
		if err != nil {
			log.Println("In user log in, password mismatch \n", err)
			render.Status(req, http.StatusBadRequest)
			render.JSON(res, req, "Please provide a valid password.")
			return
		}
		cookieValue := uuid.NewV4()
		cookieValueString := cookieValue.String()
		cookie := &http.Cookie{
			Name:     "session",
			Value:    cookieValueString,
			HttpOnly: true,
		}
		// Log in by setting in a cookie
		dba.db.InsertLoggedInUser(tempUser.Email, cookieValueString)
		http.SetCookie(res, cookie)
		log.Printf("In user log in, user was logged in by setting a new cookie")
		render.JSON(res, req, "You are logged in!")
		return
	}
	// Not signedUpUser should be asked to sign up first.
	log.Printf("In userLogin but User has not signedUp yet.")
	render.Status(req, http.StatusBadRequest)
	render.JSON(res, req, "Please sign up first.")

}

// AlreadyLoggedIn checks if the cookie is present in the client.
// If present verifies if the cookie is of the same value that was used with logging in.
func (dba Authenticator) AlreadyLoggedIn(email string, req *http.Request) (bool, error) {
	c, err := req.Cookie("session")
	if err != nil {
		if err == http.ErrNoCookie {
			return false, nil
		}
		return false, fmt.Errorf("alreadyLoggedIn: error while retrieving the cookie: %v", err)
	}
	savedCookie, err := dba.db.GetCookie(email)
	if err != nil {
		return false, fmt.Errorf("alreadyLoggedIn: %v", err)
	}
	if savedCookie != c.Value {
		return false, nil
	}
	return true, nil

}

// UserLogout is used to Logout a user by clearing the cookie present in the client.
// UserLogout first checks if the user is signed up or not. Then checks if the user is
// logged in or not.
func (dba Authenticator) UserLogout(res http.ResponseWriter, req *http.Request) {
	var tempUser User
	err := json.NewDecoder(req.Body).Decode(&tempUser)
	if err != nil {
		log.Printf("UserLogout: error for user while decoding %s: %v", tempUser.Email, err)
		render.Status(req, http.StatusInternalServerError)
		render.JSON(res, req, "Internal server Error")
		return
	}
	err, isSignedUp := dba.db.IsUserSignedUp(tempUser.Email)
	if err != nil {
		log.Printf("In sign-up error for user: %s err: %v", tempUser.Email, err)
		render.Status(req, http.StatusInternalServerError)
		render.JSON(res, req, "Internal server Error")
		return
	}
	if isSignedUp {
		isLoggedIn, err := dba.AlreadyLoggedIn(tempUser.Email, req)
		if err != nil {
			log.Println(err)
			render.Status(req, http.StatusInternalServerError)
			render.JSON(res, req, "Internal server Error")
			return
		}
		if isLoggedIn {
			// Delete cookie from client.
			cookie := &http.Cookie{
				Name:     "session",
				Value:    "",
				MaxAge:   -1,
				HttpOnly: true,
			}
			log.Printf("User %s is logged out", tempUser.Email)
			// Delete cookie from the client and delete from the DB loggedinusers table.
			// TODO: Handle the error
			dba.db.DeleteCookie(tempUser.Email)
			http.SetCookie(res, cookie)
			render.JSON(res, req, "You are logged out.")
			return
		}
		log.Printf("User %s : In userLogout but User has not LoggedIn yet.", tempUser.Email)
		render.Status(req, http.StatusBadRequest)
		render.JSON(res, req, "Please Log in first.")
		return
	}
	// Not signedUpUser should be asked to sign up first.
	log.Printf("In userLogout but User has not signedUp yet.")
	render.Status(req, http.StatusBadRequest)
	render.JSON(res, req, "Please sign up first.")

}
