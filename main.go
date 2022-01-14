package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha512"
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	mrand "math/rand"
	"net/http"
	"os"
	"strconv"
	"time"

	_ "github.com/go-sql-driver/mysql"
	_ "github.com/jackc/pgx/v4/stdlib"
	"github.com/joho/godotenv"
	_ "github.com/lib/pq"
)

type block struct {
	Id        string `json:"id"`
	Num       int    `json:"num"`
	Time      string `json:"time"`
	Type      string `json:"type"`
	User      string `json:"user"`
	Signature string `json:"signature"`
	Sum       string `json:"sum"`
	Key       string `json:"key"`
	Order     string `json:"order"`
	Message   string `json:"message"`
	Thash     string `json:"thash"`
	Phash     string `json:"phash"`
}

type chain struct {
	Blocks []block `json:"blocks"`
	Count  int     `json:"count"`
	Users  int     `json:"users"`
	Orders int     `json:"cheks"`
	Return int     `json:"return"`
}

var (
	Chain chain
	Set   []string
)

func init() {
	db, err := sql.Open("pgx", DSN())
	CheckError(err)
	if err := db.Ping(); err != nil {
		panic(err)
	}
	log.Println("database is reachable")
	defer db.Close()

	data := db.QueryRow("SELECT data FROM blockchain WHERE id=0;")
	var bin []byte
	if err := data.Scan(&bin); err != nil {
		log.Println(err)
	}
	err = json.Unmarshal(bin, &Chain)
	CheckError(err)
}

func GenerateRSAKey(bits int) (verify []byte, sign []byte) {
	privateKey, err := rsa.GenerateKey(rand.Reader, bits)
	CheckError(err)
	X509PrivateKey := x509.MarshalPKCS1PrivateKey(privateKey)
	verify = pem.Block{Type: "RSA Private Key", Bytes: X509PrivateKey}.Bytes

	publicKey := privateKey.PublicKey
	X509PublicKey, err := x509.MarshalPKIXPublicKey(&publicKey)
	CheckError(err)
	sign = pem.Block{Type: "RSA Public Key", Bytes: X509PublicKey}.Bytes

	return
}

func RSA_Encrypt(plainText []byte, signature []byte) []byte {
	publicKeyInterface, err := x509.ParsePKIXPublicKey(signature)
	if err != nil {
		panic(err)
	}
	publicKey := publicKeyInterface.(*rsa.PublicKey)
	cipherText, err := rsa.EncryptPKCS1v15(rand.Reader, publicKey, plainText)
	if err != nil {
		panic(err)
	}
	return cipherText
}

func RSA_Decrypt(cipherText []byte, verify []byte) []byte {
	privateKey, err := x509.ParsePKCS1PrivateKey(verify)
	if err != nil {
		panic(err)
	}
	plainText, _ := rsa.DecryptPKCS1v15(rand.Reader, privateKey, cipherText)
	return plainText
}

func RandString(n int) string {
	char := []rune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
	mrand.Seed(time.Now().UnixNano())
	b := make([]rune, n)
	for i := range b {
		b[i] = char[mrand.Intn(len(char))]
	}
	return string(b)
}

func DSN() string {
	err := godotenv.Load(".env")
	if err != nil {
		fmt.Println("Error loading .env file: ", err)
	}
	return os.Getenv("DSN")
}

func (c *chain) Last() *block {
	return &c.Blocks[len(c.Blocks)-1]
}

func (c *chain) Search(id string) *block {
	for _, b := range c.Blocks {
		if b.Id == id {
			return &b
		}
	}
	return &block{}
}

func (c *chain) Append(b *block) error {
	c.Count++
	switch b.Type {
	case "User":
		c.Users++
	case "Order":
		c.Orders++
	}
	num, err := strconv.Atoi(b.Sum)
	CheckError(err)
	c.Return += num
	c.Blocks = append(c.Blocks, *b)
	return nil
}

func (c *chain) Validate(b *block) (result bool) {
	switch b.Type {
	case "User":
		break
	case "COrder":
		break
	case "GOrder":
		break
	default:
		return false
	}
	return true
}

func (b *block) Hash() string {
	bytes, err := json.Marshal(b)
	if err != nil {
		fmt.Println(err)
	}
	return fmt.Sprintf("%x", sha512.Sum512(bytes))
}

func (b *block) ToString() (s string) {
	data, err := json.Marshal(b)
	CheckError(err)
	s = string(data)
	return
}

func Handler(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		w.Write([]byte("Unsupported method."))
	}
	b := block{
		Id:        RandString(256),
		Num:       Chain.Last().Num + 1,
		Time:      time.Now().String(),
		Type:      r.FormValue("Type"),
		User:      r.FormValue("User"),
		Signature: r.FormValue("Signature"),
		Sum:       r.FormValue("Sum"),
		Key:       r.FormValue("Key"),
		Order:     r.FormValue("Order"),
		Message:   r.FormValue("Message"),
		Thash:     "",
		Phash:     Chain.Last().Hash(),
	}
	switch r.URL.Path {
	case "/block":
		fmt.Fprint(w, Chain.Search(b.Id).ToString())
		return
	case "/user":
		val, sign := GenerateRSAKey(4096)
		b.Signature = string(val)
		b.User = RandString(128)
		if !Chain.Validate(&b) {
			fmt.Fprint(w, "Unsuccessful")
			return
		}
		fmt.Fprint(w, sign, b.User)
	case "/order/create":
		b.Order = RandString(128)
		if !Chain.Validate(&b) {
			fmt.Fprint(w, "Unsuccessful")
			return
		}
		fmt.Fprint(w, b.Order, b.Id)
	case "/order/get":
		if !Chain.Validate(&b) {
			fmt.Fprint(w, "Unsuccessful")
			return
		}
		fmt.Fprint(w, b.Id)
	default:
		w.Write([]byte("Unsupported action."))
		return
	}
	Chain.Append(&b)
}

func CheckError(err error) {
	if err != nil {
		log.Fatal("🍒Catched: ", err)
	}
}

func GetPort() string {
	var port = os.Getenv("PORT")
	if port == "" {
		port = "80"
		fmt.Println("INFO: No PORT environment variable detected, defaulting to " + port)
	}
	return ":" + port
}

func main() {
	// -> Entry Point
	mux := http.NewServeMux()
	mux.Handle("/", http.HandlerFunc(Handler))
	err := http.ListenAndServe(GetPort(), mux)
	CheckError(err)
}
