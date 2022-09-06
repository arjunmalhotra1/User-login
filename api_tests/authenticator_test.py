import requests
import uuid

API_URL = "http://localhost:8086"

def test_user_sign_up_bad_email():
    # Invalid email address.
    user_data = {"email": "asdsdgmail.com",
    "password":"123"}
    url = f"{API_URL}/user-sign-up"
    response = requests.post(url, json = user_data)
    assert 400 == response.status_code

def test_user_sign_up_good_email_bad_password():
    # Password not provided.
    user_data = {"email": "asdsdgmail.com"}
    url = f"{API_URL}/user-sign-up"
    response = requests.post(url, json = user_data)
    assert 400 == response.status_code

def test_user_sign_up_good_email_good_password():
    user_data = {"email": "asdsd@gmail.com", 
    "password": "123"}
    url = f"{API_URL}/user-sign-up"
    response = requests.post(url, json = user_data)
    assert 200 == response.status_code

def test_user_log_in_email_not_signed_up():
    user_data = {"email": "sadasdasdadsafd@gmail.com", 
    "password": "123"}
    url = f"{API_URL}/user-login"
    response = requests.post(url, json = user_data)
    assert 400 == response.status_code


def test_user_log_in_email_signed_up_wrong_password():
    user_data = {"email": "asdsd@gmail.com", 
    "password": "1234"}
    url = f"{API_URL}/user-login"
    response = requests.post(url, json = user_data)
    assert 400 == response.status_code

def test_user_log_in_email_signed_up_correct_password():
    user_data = {"email": "asdsd@gmail.com", 
    "password": "123"}
    url = f"{API_URL}/user-login"
    response = requests.post(url, json = user_data)
    cook = response.cookies
    sessioncookie = cook["session"]
    assert sessioncookie != ""
    assert 200 == response.status_code
