package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strconv"

	jwtmiddleware "github.com/auth0/go-jwt-middleware"
	jwt "github.com/form3tech-oss/jwt-go"
	"github.com/gin-gonic/contrib/static"
	"github.com/gin-gonic/gin"
)

const (
	AUTH0_API_CLIENT_SECRET = ``
	AUTH0_CLIENT_ID         = ``
	AUTH0_DOMAIN            = ``
	AUTH0_API_AUDIENCE      = ``
)

type Jwks struct {
	Keys []JSONWebKeys `json:"keys"`
}

type JSONWebKeys struct {
	Kty string   `json:"kty"`
	Kid string   `json:"kid"`
	Use string   `json:"use"`
	N   string   `json:"n"`
	E   string   `json:"e"`
	X5c []string `json:"x5c"`
}

type Joke struct {
	ID    int    `json:"id" binding:"required"`
	Likes int    `json:"likes"`
	Joke  string `json:"joke" binding:"required"`
}

var jokes = []Joke{
	{1, 0, "Did you hear about the restaurant on the moon? Great food, no atmosphere."},
	{2, 0, "What do you call a fake noodle? An Impasta."},
	{3, 0, "How many apples grow on a tree? All of them."},
	{4, 0, "Want to hear a joke about paper? Nevermind it's tearable."},
	{5, 0, "I just watched a program about beavers. It was the best dam program I've ever seen."},
	{6, 0, "Why did the coffee file a police report? It got mugged."},
	{7, 0, "How does a penguin build it's house? Igloos it together."},
}

var jwtMiddleWare *jwtmiddleware.JWTMiddleware

func main() {
	var getterFunc jwt.Keyfunc
	getterFunc = validationKeyGetterFunc
	jwtMiddleWare = jwtmiddleware.New(jwtmiddleware.Options{
		ValidationKeyGetter: getterFunc,
		SigningMethod:       jwt.SigningMethodRS256,
	})

	router := gin.Default()
	router.Use(static.Serve("/", static.LocalFile("./views", true)))
	api := router.Group("/api")
	{
		api.GET("/", func(c *gin.Context) {
			c.JSON(http.StatusOK, gin.H{
				"message": "pong",
			})
		})
	}
	api.GET("/jokes", authMiddleware(), JokeHandler)
	api.POST("/jokes/like/:jokeID", authMiddleware(), LikeJoke)

	router.Run(":3000")
}

func validationKeyGetterFunc(token *jwt.Token) (interface{}, error) {
	aud := AUTH0_API_AUDIENCE
	checkAudience := token.Claims.(jwt.MapClaims).VerifyAudience(aud, false)
	if !checkAudience {
		return token, errors.New("Invalid audience.")
	}
	// verify iss claim
	iss := AUTH0_DOMAIN
	checkIss := token.Claims.(jwt.MapClaims).VerifyIssuer(iss, false)
	if !checkIss {
		return token, errors.New("Invalid issuer.")
	}

	cert, err := getPemCert(token)
	if err != nil {
		log.Fatalf("could not get cert: %+v", err)
	}

	result, _ := jwt.ParseRSAPublicKeyFromPEM([]byte(cert))
	return result, nil
}

func authMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Get the client secret key
		err := jwtMiddleWare.CheckJWT(c.Writer, c.Request)
		if err != nil {
			// Token not found
			fmt.Println(err)
			c.Abort()
			c.Writer.WriteHeader(http.StatusUnauthorized)
			c.Writer.Write([]byte("Unauthorized"))
			return
		}
	}
}

func getPemCert(token *jwt.Token) (string, error) {
	cert := ""
	resp, err := http.Get(AUTH0_DOMAIN + ".well-known/jwks.json")
	if err != nil {
		return cert, err
	}
	defer resp.Body.Close()

	var jwks = Jwks{}
	err = json.NewDecoder(resp.Body).Decode(&jwks)

	if err != nil {
		return cert, err
	}

	x5c := jwks.Keys[0].X5c
	for k, v := range x5c {
		if token.Header["kid"] == jwks.Keys[k].Kid {
			cert = "-----BEGIN CERTIFICATE-----\n" + v + "\n-----END CERTIFICATE-----"
		}
	}

	if cert == "" {
		return cert, errors.New("unable to find appropriate key.")
	}

	return cert, nil
}

func JokeHandler(c *gin.Context) {
	c.Header("Content-Type", "application/json")
	c.JSON(http.StatusOK, jokes)
}

func LikeJoke(c *gin.Context) {
	jokeID, err := strconv.Atoi(c.Param("jokeID"))
	if err != nil {
		c.AbortWithStatus(http.StatusNotFound)
		return
	}
	for i := 0; i < len(jokes); i++ {
		if jokes[i].ID == jokeID {
			jokes[i].Likes++
		}
	}
	c.JSON(http.StatusOK, &jokes)
}
