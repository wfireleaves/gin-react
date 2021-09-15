package main

import (
	"net/http"
	"strconv"

	"github.com/gin-gonic/contrib/static"
	"github.com/gin-gonic/gin"
)

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

func main() {
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
	api.GET("/jokes", JokeHandler)
	api.POST("/jokes/like/:jokeID", LikeJoke)

	router.Run(":3000")
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
