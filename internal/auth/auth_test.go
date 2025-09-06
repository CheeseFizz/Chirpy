package auth

import (
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestHashPassword(t *testing.T) {
	plain_text := "TestPass"
	hashed, err := HashPassword(plain_text)
	if err != nil {
		t.Errorf("HashPassword(\"TestPass\") returned error: %v", err)
	}
	if len(hashed) == 0 {
		t.Error("HashPassword(\"TestPass\") returned empty string")
	}
}

func TestCheckPasswordHash(t *testing.T) {
	plain_text := "TestPass"
	hashed, _ := HashPassword(plain_text)

	err := CheckPasswordHash(plain_text, hashed)
	if err != nil {
		t.Errorf("CheckPasswordHash returned error: %v", err)
	}
}

func TestMakeJWT(t *testing.T) {
	test_id := uuid.New()
	secret := "CorrectHorseBatteryStaple"
	expires := 5 * time.Second

	token, err := MakeJWT(test_id, secret, expires)
	if err != nil {
		t.Errorf("MakeJWT(%v, %s, %v) returned error: %v", test_id, secret, expires, err)
	}

	if len(token) <= 1 {
		t.Errorf("MakeJWT(%v, %s, %v) returned bad token: %s", test_id, secret, expires, token)
	}
}

func TestValidateJWT(t *testing.T) {
	test_id := uuid.New()
	secret := "CorrectHorseBatteryStaple"
	expires := 5 * time.Second

	token, _ := MakeJWT(test_id, secret, expires)

	response, err := ValidateJWT(token, secret)
	if err != nil {
		t.Errorf("ValidateJWT(%s, %s) returned err: %v", token, secret, err)
	}
	if response != test_id {
		t.Errorf("ValidateJWT() | expected: %s | actual: %s", test_id, response)
	}

	time.Sleep(expires)

	_, err = ValidateJWT(token, secret)
	if err == nil {
		t.Errorf("ValidateJWT did not return error for expired token")
	}
}

func TestGetBearerToken(t *testing.T) {
	test_id := uuid.New()
	secret := "CorrectHorseBatteryStaple"
	expires := 5 * time.Second

	token, _ := MakeJWT(test_id, secret, expires)
	head := make(http.Header)
	head.Add("Authorization", fmt.Sprintf("Bearer %s", token))
	head.Add("Content-Type", "application/json")

	result, err := GetBearerToken(head)
	if err != nil {
		t.Errorf("GetBearerToken returned error: %v", err)
	}

	if result != token {
		t.Errorf("GetBearerToken | expected: %s | actual %s", token, result)
	}
}
