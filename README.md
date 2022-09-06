# application-UserLogin
This application is an API that allows users to sign up for an imaginary website and log in securely.

## How to run the project
	make docker-compose-up  

## How to run the Unit-tests
    make unit-tests
## How to run the API-tests
 ### First Run the project
    make api-tests

## How to generate go docs
  make godoc
  Then on your browser go to - http://localhost:6060/pkg/github.com/arjunmalhotra1/application-UserLogin/authenticator/

## Assumptions
* User email is a string and a valid email address.
* User password is a string.
* Users are signed and logged out using a cookie.


## POST /user-sign-up
  * email - required & needs to be a valid email address.
  * password - required & is of type string.
    > A valid request looks like:

        {
            "email" : "asdfdffdfdf@ttt.com",
            "password" :"123"
        }

## POST /user-login
  * User needs to be a signed up user first.
  * email - required & needs to be a valid email address.
  * password - required & is of type string.
    > A valid request looks like:

        {
            "email" : "asdfdffdfdf@ttt.com",
            "password" :"123"
        }
## POST /user-logout
  * email - required & needs to be a valid email address.
  * User needs to be signed up and logged in first.
    > A valid request looks like:

        {
            "email" : "asdfdffdfdf@ttt.com",
        }

### POSTMAN
[![Run in Postman](https://run.pstmn.io/button.svg)](https://app.getpostman.com/run-collection/ea90b2d04508029a487c)