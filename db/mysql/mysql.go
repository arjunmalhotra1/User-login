package mysql

import (
	"database/sql"
	"fmt"
	"log"
	"os"

	"github.com/arjunmalhotra1/application-UserLogin/authenticator"
	"github.com/go-sql-driver/mysql"
)

//var MysqlDb *sql.DB

type MysqlDb struct {
	db *sql.DB
}

func NewDBConnection() (db *sql.DB) {
	cfg := mysql.Config{
		User:                 os.Getenv("MYSQL_USER"),
		Passwd:               os.Getenv("MYSQL_PASSWORD"),
		Net:                  "tcp",
		Addr:                 fmt.Sprintf(os.Getenv("MYSQL_HOST") + ":3307"),
		DBName:               os.Getenv("MYSQL_DB"),
		AllowNativePasswords: true,
	}
	var err error

	sqlDb, err := sql.Open("mysql", cfg.FormatDSN())
	if err != nil {
		log.Fatal("Couldn't connect to the database", err)
	}
	pingErr := sqlDb.Ping()
	if pingErr != nil {
		log.Fatal(pingErr)
	}
	fmt.Println("Connected!")
	return sqlDb
}

func New() *MysqlDb {
	dbConnection := NewDBConnection()
	return &MysqlDb{
		db: dbConnection,
	}
}

// IsUserSignedUp is used to check if a user is signed up or not.
func (msd MysqlDb) IsUserSignedUp(email string) (error, bool) {
	var tempUser authenticator.User
	var id int
	row := msd.db.QueryRow("Select * FROM signedupusers WHERE email = ?", email)
	if err := row.Scan(&id, &tempUser.Email, &tempUser.Password); err != nil {
		if err == sql.ErrNoRows {
			return nil, false
		}
		return fmt.Errorf("error while retrieving the row %v", err), false
	}
	return nil, true
}

// InsertSignedUpUser is used to insert the user in the database.
func (msd MysqlDb) InsertSignedUpUser(tempUser authenticator.User) error {
	result, err := msd.db.Exec("INSERT INTO signedupusers (email,pass) VALUES (?,?)", tempUser.Email, tempUser.Password)
	if err != nil {
		return fmt.Errorf("InsertSignedUpUser: %v", err)
	}
	_, err = result.LastInsertId()
	if err != nil {
		return fmt.Errorf("InsertSignedUpUser: %v", err)
	}
	return nil
}

// InsertLoggedInUser is used to insert the logged in user in the database.
func (msd MysqlDb) InsertLoggedInUser(email string, uniqueCookie string) error {
	result, err := msd.db.Exec("INSERT INTO loggedinusers (email,cookie) VALUES (?,?) ON DUPLICATE KEY UPDATE cookie = ?", email, uniqueCookie, uniqueCookie)

	if err != nil {
		return fmt.Errorf("InsertLoggedInUSer: %v", err)
	}
	_, err = result.LastInsertId()
	if err != nil {
		return fmt.Errorf("InsertLoggedInUSer: %v", err)
	}
	return nil
}

// GetEncryptedPass is used to get the encrypted password of a user.
func (msd MysqlDb) GetEncryptedPass(email string) (string, error) {
	var tempUser authenticator.User
	var id int
	row := msd.db.QueryRow("Select * FROM signedupusers WHERE email = ?", email)
	if err := row.Scan(&id, &tempUser.Email, &tempUser.Password); err != nil {
		if err == sql.ErrNoRows {
			return "", fmt.Errorf("user %s is not logged in %v", email, err)
		}
		return "", fmt.Errorf("error while retrieving the row %v", err)
	}
	return tempUser.Password, nil
}

// GetCookie returns the set cookie used while logging a user from the database.
func (msd MysqlDb) GetCookie(email string) (string, error) {
	var cookieString string
	row := msd.db.QueryRow("Select cookie FROM loggedinusers WHERE email = ?", email)
	if err := row.Scan(&cookieString); err != nil {
		if err == sql.ErrNoRows {
			return "", nil
		}
		return "", fmt.Errorf("GetCookie : error while retrieving the row: %v", err)
	}
	return cookieString, nil
}

// DeleteCookie is used to delete the cookie from the database. Used to logout a user.
func (msd MysqlDb) DeleteCookie(email string) bool {
	res, err := msd.db.Exec("DELETE FROM loggedinusers WHERE email = ?", email)
	// TODO: Fix this logic to handle errors.
	if err == nil {
		count, err := res.RowsAffected()
		if err == nil {
			if count == 1 {
				return true
			}
		}
	}
	return false

}
