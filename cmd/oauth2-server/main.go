package main

import (
	"encoding/json"
	"fmt"
	"github.com/go-oauth2/oauth2/v4/errors"
	"github.com/go-oauth2/oauth2/v4/manage"
	"github.com/go-oauth2/oauth2/v4/models"
	"github.com/go-oauth2/oauth2/v4/server"
	"github.com/go-oauth2/oauth2/v4/store"
	"github.com/google/uuid"
	"log"
	"net/http"
)

// User holds user information
type User struct {
	Username string `json:"username"`
	APIKey   string `json:"api_key"`
	Secret   string `json:"secret"`
}

var users = make(map[string]*User)

func main() {
	manager := manage.NewDefaultManager()

	// Using JWT tokens
	manager.MapTokenStorage(store.NewMemoryTokenStore())
	manager.MapAccessGenerate(&JWTAccessGenerate{})

	clientStore := store.NewClientStore()
	manager.MapClientStorage(clientStore)

	srv := server.NewDefaultServer(manager)
	srv.SetAllowGetAccessRequest(true)
	srv.SetClientInfoHandler(server.ClientFormHandler)
	srv.SetPasswordAuthorizationHandler(passwordAuthHandler)
	srv.SetInternalErrorHandler(func(err error) (re *errors.Response) {
		log.Println("Internal Error:", err.Error())
		return
	})
	srv.SetResponseErrorHandler(func(re *errors.Response) {
		log.Println("Response Error:", re.Error.Error())
	})

	// Create a new user
	http.HandleFunc("/register", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		username := r.FormValue("username")
		if username == "" {
			http.Error(w, "Username is required", http.StatusBadRequest)
			return
		}

		apiKey := uuid.New().String()
		secret := uuid.New().String()

		clientStore.Set(apiKey, &models.Client{
			ID:     apiKey,
			Secret: secret,
			Domain: "",
		})

		user := &User{
			Username: username,
			APIKey:   apiKey,
			Secret:   secret,
		}

		users[username] = user

		response, err := json.Marshal(user)
		if err != nil {
			http.Error(w, "Error creating user", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.Write(response)
	})

	// OAuth2 Token URL
	http.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		err := srv.HandleTokenRequest(w, r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
		}
	})

	// JWKs endpoint
	http.HandleFunc("/.well-known/jwks.json", jwksHandler)

	log.Println("Server is running on port 8080...")
	log.Fatal(http.ListenAndServe(":8080", nil))
}

// JWTAccessGenerate is a custom token generator
type JWTAccessGenerate struct {
}

// Token generates a new JWT token
func (g *JWTAccessGenerate) Token(data *oauth2.GenerateBasic, isGenRefresh bool) (access, refresh string, err error) {
	token := jwt.New(jwt.SigningMethodHS256)

	claims := token.Claims.(jwt.MapClaims)
	claims["sub"] = data.UserID
	claims["aud"] = data.Client.GetID()
	claims["iat"] = jwt.NewNumericDate(jwt.TimeFunc())
	claims["exp"] = jwt.NewNumericDate(jwt.TimeFunc().Add(data.TokenInfo.GetAccessExpiresIn()))

	tokenStr, err := token.SignedString([]byte("secret")) // Change this to a secure secret key
	if err != nil {
		return "", "", err
	}

	return tokenStr, "", nil
}

func passwordAuthHandler(username, password string) (userID string, err error) {
	// Simple password authentication, adjust as needed
	user, ok := users[username]
	if !ok {
		return "", fmt.Errorf("user not found")
	}

	if user.Secret != password {
		return "", fmt.Errorf("invalid password")
	}

	return username, nil
}

func jwksHandler(w http.ResponseWriter, r *http.Request) {
	keys := struct {
		Keys []map[string]interface{} `json:"keys"`
	}{
		Keys: []map[string]interface{}{
			{
				"kty": "RSA",
				"alg": "RS256",
				"use": "sig",
				"kid": "1",
				"n":   "public_key_modulus", // Use the actual modulus of the RSA key
				"e":   "AQAB",
			},
		},
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(keys)
}
