package main

import (
	"fmt"
	"net/http"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
)

var jwtKey = []byte("secret-key")

var users = map[string]string{
	"user1": "password1",
	"user2": "password2",
}

type Claims struct {
	Username string `json: "username"`
	jwt.StandardClaims
}

type Credentials struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

func Login(c *gin.Context) {
	var credentials Credentials
	err := c.ShouldBindJSON(&credentials) //c.shouldbind is equivalent to http.request
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"status": "bad request",
		}) //c.json is equivalent to http.responsewriter
		return
	}

	expectedPassword, ok := users[credentials.Username]

	if !ok || expectedPassword != credentials.Password {
		c.JSON(http.StatusUnauthorized, gin.H{
			"status": "unauthorized",
		})
		return
	}

	expirationTime := time.Now().Add(time.Minute * 5)

	claims := &Claims{
		Username: credentials.Username,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: expirationTime.Unix(),
		},
	}

	//using claims and jwt secret key to generate a tokenstring
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString(jwtKey)

	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"status": "Internal server Error",
		})
		return
	}

	cookie, err := c.Cookie("token")

	if err != nil {
		cookie = "NOTSET"
		c.SetCookie("token", tokenString, 3600, "/login", "localhost:8010", false, true)

	}

	fmt.Printf("Cookie value: %s \n", cookie)

}


func Home(c *gin.Context) {
	cookie, err := c.Cookie("token")
	if err != nil {
		if err == http.ErrNoCookie {
			c.JSON(http.StatusUnauthorized, gin.H {
				"status": "unautorized",
			})
		}
	}
}
