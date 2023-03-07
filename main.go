package main

import (
  "net/http"
  "github.com/gin-gonic/gin"
  "github.com/golang-jwt/jwt/v4"
  "time"
  "encoding/pem"
  "crypto/x509"
  "os"
  "math/rand"
)

type Body struct {
	// json tag to de-serialize json body
	AppName string `json:"appName"`
	AppUserIdList []string `json:"AppUserIdList"`
	ContentIdList []string `json:"ContentIdList"`
	SecretKey string `json:"secretKey"`
}

func main() {
  r := gin.Default()

  r.GET("/", func(c *gin.Context) {
    c.JSON(http.StatusOK, gin.H{
      "message": "Hello world",
    })
  })

  r.GET("/ping", func(c *gin.Context) {
	srvName := os.Getenv("SERVICE_NAME")
    c.JSON(http.StatusOK, gin.H{
      "message": srvName,
    })
  })

  r.POST("/generate-token", func(c *gin.Context) {
	body:=Body{}
	if err:=c.BindJSON(&body); err!=nil {
		c.AbortWithError(http.StatusBadRequest,err)
	   return
	}
	tokenList := []string{}
	for i := 1; i < len(body.AppUserIdList); i++ {
		token, _ := generateJWT(body.AppName, body.AppUserIdList[i], body.ContentIdList[rand.Intn(len(body.ContentIdList))], body.SecretKey)
		tokenList = append(tokenList, token)
	}

    c.JSON(http.StatusOK, gin.H{
      "token": tokenList,
    })
  })
  r.Run() // listen and serve on 0.0.0.0:8080 (for windows "localhost:8080")
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
