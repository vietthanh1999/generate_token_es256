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

type Profile struct {
	Id string `json:"id"`
	PhoneNumber string `json:"phoneNumber"`
	FirstName string `json:"firstName"`
	LastName string `json:"lastName"`
	Email string `json:"email"` 
	CreatedBy string `json:"createdBy"`
	UpdatedBy string `json:"updatedBy"` 
	CreatedAt int `json:"createdAt"` 
	UpdatedAt int `json:"updatedAt"`
}

type ClaimsInfo struct {
	Profile Profile `json:"profile"`
	Aud string `json:"aud"`
	Iss string `json:"iss"`
	Sub string `json:"sub"`
	Iat int `json:"iat"`
	Exp int `json:"exp"`
} 

type InteractiveBody struct {
	// json tag to de-serialize json body
	Profiles []ClaimsInfo `json:"profiles"`
	SecretKey string `json:"secretKey"`
}

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
		for i := 0; i < len(body.AppUserIdList); i++ {
			token, _ := generateJWT(body.AppName, body.AppUserIdList[i], body.ContentIdList[rand.Intn(len(body.ContentIdList))], body.SecretKey)
			tokenList = append(tokenList, token)
		}

		c.JSON(http.StatusOK, gin.H{
		"token": tokenList,
		})
	})

	r.POST("/generate-token-to-interactive", func(c *gin.Context) {
		body:=InteractiveBody{}
		if err:=c.BindJSON(&body); err!=nil {
			c.AbortWithError(http.StatusBadRequest,err)
		return
		}
		tokenList := []string{}
		for i := 0; i < len(body.Profiles); i++ {
			token, _ := generateJWTToInteractive(body.Profiles[i], body.SecretKey)
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

func generateJWTToInteractive(claimsInfo ClaimsInfo, secretKey string) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{
		"profile": jwt.MapClaims{
			"id": claimsInfo.Profile.Id,
			"phoneNumber": claimsInfo.Profile.PhoneNumber,
			"firstName": claimsInfo.Profile.FirstName,
			"lastName": claimsInfo.Profile.LastName,
			"email": claimsInfo.Profile.Email,
			"createdBy": claimsInfo.Profile.CreatedBy,
			"updatedBy": claimsInfo.Profile.UpdatedBy,
			"createdAt": claimsInfo.Profile.CreatedAt,
			"updatedAt": claimsInfo.Profile.UpdatedAt,
		},
		"aud": claimsInfo.Aud,
		"iss": claimsInfo.Iss,
		"sub": claimsInfo.Sub,
		"iat": claimsInfo.Iat,
		"exp": claimsInfo.Exp,
	})
	block, _ := pem.Decode([]byte(secretKey))
	key, _ := x509.ParsePKCS8PrivateKey(block.Bytes)

	tokenString, err := token.SignedString(key)
	if err != nil {
		return "Signing Error", err
	}

	return tokenString, err
}

