package hash

import (
	"strings"

	"golang.org/x/crypto/bcrypt"
)

func CreateInput(tokens []string) string {
	return strings.Join(tokens, "@")
}

func HashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(bytes), err
}

func CheckPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}
