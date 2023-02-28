package main

import (
  "net/http"
  "github.com/gin-gonic/gin"
  "github.com/golang-jwt/jwt/v4"
  "time"
  "encoding/pem"
  "crypto/x509"
)

func main() {
  r := gin.Default()
  r.GET("/ping", func(c *gin.Context) {
    c.JSON(http.StatusOK, gin.H{
      "message": "pong",
    })
  })

  r.POST("/generate-token", func(c *gin.Context) {
	appName := c.DefaultPostForm("appName", "")
	appUserId := c.DefaultPostForm("appUserId", "")
	contentId := c.DefaultPostForm("contentId", "")
	secretKey := c.DefaultPostForm("secretKey", "")
	token, _ := generateJWT(appName, appUserId, contentId, secretKey)

    c.JSON(http.StatusOK, gin.H{
      "token": token,
    })
  })
  r.Run(":8888") // listen and serve on 0.0.0.0:8080 (for windows "localhost:8080")
}

func generateJWT(appName string, appUserId string, contentId string, secretKey string) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{
		"exp": time.Now().AddDate(2, 0, 0).Unix(),
		"app_name": appName,
		"app_user_id": appUserId,
		"content_id":contentId,
	})
	block, _ := pem.Decode([]byte(secretKey))
	key, _ := x509.ParsePKCS8PrivateKey(block.Bytes)

	tokenString, err := token.SignedString(key)
	if err != nil {
		return "Signing Error", err
	}

	return tokenString, err
}
