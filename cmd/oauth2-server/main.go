package main

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"math/big"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/go-oauth2/oauth2/v4"
	"github.com/go-oauth2/oauth2/v4/errors"
	"github.com/go-oauth2/oauth2/v4/manage"
	"github.com/go-oauth2/oauth2/v4/models"
	"github.com/go-oauth2/oauth2/v4/server"
	"github.com/go-oauth2/oauth2/v4/store"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

var (
	privateKey *rsa.PrivateKey
	publicKey  *rsa.PublicKey
)

// User holds user information
type User struct {
	Username string `json:"username"`
	APIKey   string `json:"api_key"`
	Secret   string `json:"secret"`
}

var users = make(map[string]*User)

func main() {
	// Command-line flags for key files
	privateKeyPath := flag.String("private_key", "private_key.pem", "Path to the RSA private key file")
	publicKeyPath := flag.String("public_key", "public_key.pem", "Path to the RSA public key file")
	flag.Parse()

	// Load keys from the provided file paths
	err := loadKeys(*privateKeyPath, *publicKeyPath)
	if err != nil {
		log.Fatalf("Failed to load keys: %v", err)
	}

	manager := manage.NewDefaultManager()

	// Using JWT tokens
	ts, err := store.NewMemoryTokenStore()
	if err != nil {
		log.Fatal(err)
	}
	manager.MapTokenStorage(ts)
	manager.MapAccessGenerate(&JWTAccessGenerate{})

	clientStore := store.NewClientStore()
	manager.MapClientStorage(clientStore)

	srv := server.NewDefaultServer(manager)
	srv.SetAllowGetAccessRequest(true)
	srv.SetClientInfoHandler(server.ClientFormHandler)
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
		if r.FormValue("grant_type") != "client_credentials" {
			http.Error(w, fmt.Sprintf("Invalid grant type: %s", r.FormValue("grant_type")), http.StatusBadRequest)
			return
		}
		err = srv.HandleTokenRequest(w, r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
		}
	})

	// JWKs endpoint
	http.HandleFunc("/.well-known/jwks.json", jwksHandler)

	log.Println("Server is running on port 8282...")
	log.Fatal(http.ListenAndServe(":8282", nil))
}

// JWTAccessGenerate is a custom token generator
type JWTAccessGenerate struct {
}

// Token generates a new JWT token
func (g *JWTAccessGenerate) Token(ctx context.Context, data *oauth2.GenerateBasic, isGenRefresh bool) (access, refresh string, err error) {
	token := jwt.New(jwt.SigningMethodRS256)

	t := time.Now().UTC()
	claims := token.Claims.(jwt.MapClaims)
	claims["sub"] = data.UserID
	claims["aud"] = data.Client.GetID()
	claims["iat"] = jwt.NewNumericDate(t)
	claims["exp"] = jwt.NewNumericDate(t.Add(data.TokenInfo.GetAccessExpiresIn()))

	tokenStr, err := token.SignedString(privateKey) // Use the RSA private key
	if err != nil {
		return "", "", err
	}

	return tokenStr, "", nil
}

func jwksHandler(w http.ResponseWriter, r *http.Request) {
	// Convert the RSA public key to the appropriate format
	n := publicKey.N
	e := publicKey.E

	keys := struct {
		Keys []map[string]interface{} `json:"keys"`
	}{
		Keys: []map[string]interface{}{
			{
				"kty": "RSA",
				"alg": "RS256",
				"use": "sig",
				"kid": "1",
				"n":   encodeBase64(n.Bytes()),
				"e":   encodeBase64(big.NewInt(int64(e)).Bytes()),
			},
		},
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(keys)
}

func encodeBase64(b []byte) string {
	return strings.TrimRight(base64.URLEncoding.EncodeToString(b), "=")
}

// loadKeys loads RSA keys from files
func loadKeys(privateKeyPath, publicKeyPath string) error {
	// Load private key
	privKeyData, err := os.ReadFile(privateKeyPath)
	if err != nil {
		return fmt.Errorf("failed to read private key file: %v", err)
	}
	privBlock, _ := pem.Decode(privKeyData)
	if privBlock == nil || (privBlock.Type != "RSA PRIVATE KEY" && privBlock.Type != "PRIVATE KEY") {
		return fmt.Errorf("failed to decode PEM block containing private key")
	}

	// Parse PKCS#8 or PKCS#1 format
	if privBlock.Type == "PRIVATE KEY" {
		privateKeyInterface, err := x509.ParsePKCS8PrivateKey(privBlock.Bytes)
		if err != nil {
			return fmt.Errorf("failed to parse PKCS#8 private key: %v", err)
		}
		privateKey = privateKeyInterface.(*rsa.PrivateKey)
	} else {
		privateKey, err = x509.ParsePKCS1PrivateKey(privBlock.Bytes)
		if err != nil {
			return fmt.Errorf("failed to parse PKCS#1 private key: %v", err)
		}
	}

	// Load public key
	pubKeyData, err := os.ReadFile(publicKeyPath)
	if err != nil {
		return fmt.Errorf("failed to read public key file: %v", err)
	}
	pubBlock, _ := pem.Decode(pubKeyData)
	if pubBlock == nil || pubBlock.Type != "PUBLIC KEY" {
		return fmt.Errorf("failed to decode PEM block containing public key")
	}
	pubInterface, err := x509.ParsePKIXPublicKey(pubBlock.Bytes)
	if err != nil {
		return fmt.Errorf("failed to parse public key: %v", err)
	}
	var ok bool
	publicKey, ok = pubInterface.(*rsa.PublicKey)
	if !ok {
		return fmt.Errorf("not an RSA public key")
	}

	return nil
}
