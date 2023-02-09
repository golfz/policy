package main

import (
	"embed"
	"errors"
	"fmt"
	"github.com/golang-jwt/jwt/v4"
	"github.com/mastertech-hq/authority/jwtutils"
	"html/template"
	"net/http"
	"os"
	"time"
)

//type Page struct {
//	Title string
//	Body  []byte
//}

//go:embed web
var webDir embed.FS

type CustomClaims struct {
	Uid       string `json:"uid"`
	UserType  string `json:"user_type"`
	TokenType string `json:"token_type"`
}

type LoginPageData struct {
	LoginAction string
}

func main() {
	http.HandleFunc("/oauth/v2/web/login", loginPage)
	fmt.Println("ready.")
	http.ListenAndServe(":8080", nil)
}

func loginPage(w http.ResponseWriter, r *http.Request) {
	data := LoginPageData{
		LoginAction: "/action/login",
	}
	printPage(w, "login.html", data)
}

func printPage(w http.ResponseWriter, fileName string, data interface{}) error {
	//t, _ := template.ParseFiles(fmt.Sprintf("./web/%s", fileName))
	t, err := template.ParseFS(webDir, "web/login.html")
	if err != nil {
		panic(err)
	}
	return t.Execute(w, data)
}

func loadPage(filename string) (string, error) {
	b, err := os.ReadFile(fmt.Sprintf("./web/%s", filename))
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func PrintClaims() {
	customClaims := CustomClaims{
		Uid:       "d7dded03-833f-453a-9e26-860244a475bf",
		UserType:  "employee",
		TokenType: "access",
	}
	token, err := jwtutils.GenerateToken(customClaims, 6*time.Second, nil)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(token)

	time.Sleep(2 * time.Second)

	_, err = jwtutils.ParseToken(token)
	if err != nil {
		fmt.Println(err)
		if errors.Is(err, jwt.ErrTokenExpired) {
			fmt.Println(">>>> token expired")
		}
		return
	}

	us, err := jwtutils.GetCustomClaimString(token, "uid")
	if err != nil {
		fmt.Println(">>>> custom claims not ok", err)
		return
	}

	fmt.Printf(">>>> claims: %+v\n", us)
}
