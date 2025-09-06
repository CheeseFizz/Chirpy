package auth

import (
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"
)

func HashPassword(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), 15)
	if err != nil {
		return "", err
	}

	return string(hash), nil
}

func CheckPasswordHash(password, hash string) error {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err
}

func MakeJWT(userID uuid.UUID, tokenSecret string, expiresIn time.Duration) (string, error) {
	claims := jwt.RegisteredClaims{
		Issuer:    "chirpy",
		IssuedAt:  jwt.NewNumericDate(time.Now()),
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(expiresIn)),
		Subject:   userID.String(),
	}
	newJWT := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signedJWT, err := newJWT.SignedString([]byte(tokenSecret))
	if err != nil {
		log.Printf("Error signing JWT: %v", err)
	}

	return signedJWT, nil
}

func ValidateJWT(tokenString, tokenSecret string) (uuid.UUID, error) {
	claims := jwt.RegisteredClaims{}
	token, err := jwt.ParseWithClaims(
		tokenString,
		&claims,
		func(token *jwt.Token) (any, error) {
			return []byte(tokenSecret), nil
		},
		jwt.WithValidMethods([]string{jwt.SigningMethodHS256.Alg()}),
	)
	if err != nil {
		return uuid.Nil, err
	}

	token_uid, err := token.Claims.GetSubject()
	if err != nil {
		return uuid.Nil, err
	}
	user_id, err := uuid.Parse(token_uid)
	if err != nil {
		return uuid.Nil, err
	}

	return user_id, nil
}

func GetBearerToken(headers http.Header) (string, error) {
	token_string, ok := headers["Authorization"]
	if !ok {
		return "", fmt.Errorf("no token in header")
	}
	token := strings.Join(token_string, "")
	token = strings.ReplaceAll(token, "Bearer", "")
	token = strings.Trim(token, " ")

	return token, nil
}
