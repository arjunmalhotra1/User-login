package authenticator

import (
	"fmt"
	"testing"

	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
)

func TestUserSignUpBeforeInsert(t *testing.T) {
	mockctrl := gomock.NewController(t)
	accessor := NewMockdbAccessor(mockctrl)
	testEmail := "abc@gmail.com"
	testPass := "1234"
	testUser := User{
		Email:    testEmail,
		Password: testPass,
	}
	accessor.EXPECT().InsertSignedUpUser(testUser).Return(nil)
	accessor.EXPECT().IsUserSignedUp(testEmail).Return(nil, false)
	err, beforeSignup := accessor.IsUserSignedUp(testEmail)
	assert.Equal(t, beforeSignup, false)
	assert.Nil(t, err)
	result := accessor.InsertSignedUpUser(testUser)
	assert.Nil(t, result)
	mockctrl.Finish()

}

func TestUserSignUpAfterInsertPositive(t *testing.T) {
	mockctrl := gomock.NewController(t)
	accessor := NewMockdbAccessor(mockctrl)
	testEmail := "abc@gmail.com"
	testPass := "1234"
	testUser := User{
		Email:    testEmail,
		Password: testPass,
	}
	gomock.InOrder(
		accessor.EXPECT().IsUserSignedUp(testEmail).Return(nil, false).Times(1),
		accessor.EXPECT().InsertSignedUpUser(testUser).Return(nil).Times(1),
		accessor.EXPECT().IsUserSignedUp(testEmail).Return(nil, true).Times(1),
	)
	err, beforeSignup := accessor.IsUserSignedUp(testEmail)
	assert.Equal(t, beforeSignup, false)
	assert.Nil(t, err)
	result := accessor.InsertSignedUpUser(testUser)
	assert.Nil(t, result)
	err, afterSignup := accessor.IsUserSignedUp(testEmail)
	assert.Equal(t, afterSignup, true)
	assert.Nil(t, err)
	mockctrl.Finish()

}

func TestUserSignUpAfterInsertNegative(t *testing.T) {
	mockctrl := gomock.NewController(t)
	accessor := NewMockdbAccessor(mockctrl)
	testEmail := "abc@gmail.com"
	testBadEmail := "abcasdsda@gmail.com"
	testPass := "1234"
	testUser := User{
		Email:    testEmail,
		Password: testPass,
	}
	gomock.InOrder(
		accessor.EXPECT().IsUserSignedUp(testEmail).Return(nil, false).Times(1),
		accessor.EXPECT().InsertSignedUpUser(testUser).Return(nil).Times(1),
		accessor.EXPECT().IsUserSignedUp(testBadEmail).Return(fmt.Errorf("This email is not present"), false).Times(1),
	)
	err, beforeSignup := accessor.IsUserSignedUp(testEmail)
	assert.Equal(t, beforeSignup, false)
	assert.Nil(t, err)
	result := accessor.InsertSignedUpUser(testUser)
	assert.Nil(t, result)
	err, afterSignup := accessor.IsUserSignedUp(testBadEmail)
	assert.Equal(t, afterSignup, false)
	assert.NotNil(t, err)
	mockctrl.Finish()
}

func TestInsertLoggedInUserAfterSignUpPositive(t *testing.T) {
	mockctrl := gomock.NewController(t)
	accessor := NewMockdbAccessor(mockctrl)
	testEmail := "abc@gmail.com"
	testCookie := "6437b032-874e-4bfa-b871-464b89d15227"
	gomock.InOrder(
		accessor.EXPECT().IsUserSignedUp(testEmail).Return(nil, true).Times(1),
		accessor.EXPECT().GetCookie(testEmail).Return("", nil).Times(1),
		accessor.EXPECT().InsertLoggedInUser(testEmail, testCookie).Return(nil).Times(1),
		accessor.EXPECT().GetCookie(testEmail).Return(testCookie, nil).Times(1),
	)
	err, isUserSignedUp := accessor.IsUserSignedUp(testEmail)
	assert.Equal(t, isUserSignedUp, true)
	assert.Nil(t, err)
	cookie, err := accessor.GetCookie(testEmail)
	assert.Equal(t, cookie, "")
	assert.Nil(t, err)
	result := accessor.InsertLoggedInUser(testEmail, testCookie)
	assert.Nil(t, result)
	cookie, err = accessor.GetCookie(testEmail)
	assert.Equal(t, cookie, testCookie)
	assert.Nil(t, err)
}

func TestInsertLoggedInUserAfterSignUpNegative(t *testing.T) {
	mockctrl := gomock.NewController(t)
	accessor := NewMockdbAccessor(mockctrl)
	testEmail := "abc@gmail.com"
	testCookie := "6437b032-874e-4bfa-b871-464b89d15227"
	testBadCookie := "6437b032-874e-4bfa-b871-464b89d15227-asdasdasasd"
	gomock.InOrder(
		accessor.EXPECT().IsUserSignedUp(testEmail).Return(nil, true).Times(1),
		accessor.EXPECT().GetCookie(testEmail).Return("", nil).Times(1),
		accessor.EXPECT().InsertLoggedInUser(testEmail, testCookie).Return(nil).Times(1),
		accessor.EXPECT().GetCookie(testEmail).Return(testCookie, fmt.Errorf("Bad Cookie!")).Times(1),
	)
	err, isUserSignedUp := accessor.IsUserSignedUp(testEmail)
	assert.Equal(t, isUserSignedUp, true)
	assert.Nil(t, err)
	cookie, err := accessor.GetCookie(testEmail)
	assert.Equal(t, cookie, "")
	assert.Nil(t, err)
	result := accessor.InsertLoggedInUser(testEmail, testCookie)
	assert.Nil(t, result)
	cookie, err = accessor.GetCookie(testEmail)
	assert.NotEqual(t, cookie, testBadCookie)
	assert.NotNil(t, err)

}
