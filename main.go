package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"log"
	"net/http"

	_ "github.com/lib/pq"
)

// Fungsi untuk menghasilkan kunci enkripsi dari password
func deriveKey(password string) []byte {
	hash := sha256.Sum256([]byte(password))
	return hash[:]
}

// Fungsi untuk mengenkripsi data
func encrypt(data, passphrase string) (string, error) {
	block, _ := aes.NewCipher(deriveKey(passphrase))
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	ciphertext := gcm.Seal(nonce, nonce, []byte(data), nil)
	return base64.URLEncoding.EncodeToString(ciphertext), nil
}

// Fungsi untuk mendekripsi data
func decrypt(encryptedData, passphrase string) (string, error) {
	data, err := base64.URLEncoding.DecodeString(encryptedData)
	if err != nil {
		return "", err
	}
	block, _ := aes.NewCipher(deriveKey(passphrase))
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonceSize := gcm.NonceSize()
	nonce, ciphertext := data[:nonceSize], data[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}
	return string(plaintext), nil
}

type App struct {
	DB *sql.DB
}

func (app *App) homeHandler(w http.ResponseWriter, r *http.Request) {
	tmpl, _ := template.ParseFiles("index.html")
	tmpl.Execute(w, nil)
}

func (app *App) addDataHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		data := r.FormValue("data")
		password := "password_kuat"

		encryptedData, err := encrypt(data, password)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		_, err = app.DB.Exec(`INSERT INTO secure_data (data) VALUES ($1)`, encryptedData)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		http.Redirect(w, r, "/", http.StatusSeeOther)
	}
}

func (app *App) getDataHandler(w http.ResponseWriter, r *http.Request) {
	rows, err := app.DB.Query(`SELECT data FROM secure_data`)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	password := "password_kuat"
	var data []string
	for rows.Next() {
		var encryptedData string
		if err := rows.Scan(&encryptedData); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		decryptedData, err := decrypt(encryptedData, password)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		data = append(data, decryptedData)
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(data)
}

func main() {
	connStr := "user=yasid password=password dbname=securedb sslmode=disable"
	db, err := sql.Open("postgres", connStr)
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	_, err = db.Exec(`CREATE TABLE IF NOT EXISTS secure_data (id SERIAL PRIMARY KEY, data TEXT)`)
	if err != nil {
		log.Fatal(err)
	}

	app := &App{DB: db}

	http.HandleFunc("/", app.homeHandler)
	http.HandleFunc("/add", app.addDataHandler)
	http.HandleFunc("/data", app.getDataHandler)

	fmt.Println("Server running on port 8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
