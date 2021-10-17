package main

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"

	"github.com/dgrijalva/jwt-go"
)

type execution struct {
	ExecutionTime time.Duration `json:"executionTime"`
	Function string `json:"function"`
}

var executions  []execution

type authStat struct {
	TotalTime time.Duration `json:"totalTime"`
	AverageTime string `json:"averageTime"`
	TotalExecutions int64 `json:"totalExecutions"`
}

type verifyStat struct {
	TotalTime time.Duration `json:"totalTime"`
	AverageTime string `json:"averageTime"`
	TotalExecutions int64 `json:"totalExecutions"`
}

type stat struct {
	AuthStat authStat `json:"authStat"`
	VerifyStat verifyStat `json:"verifyStat"`
}

func main() {
	router := gin.Default()

	router.GET("/stats", getStats)
	router.GET("/auth/:username", getAuthByUsername)
	router.GET("/verify", verifyJWT)

	router.GET("/README.txt", sendREADME)

	router.Run("localhost:8080")
}



func getStats(c *gin.Context) {
	if len(executions) == 0 {
		c.String(http.StatusInternalServerError, "No Stats to show yet.")
		return
	}

	var auth = authStat{
		TotalTime:       0,
		AverageTime:     "",
		TotalExecutions: 0,
	}
	var verify = verifyStat{
		TotalTime:       0,
		AverageTime:     "",
		TotalExecutions: 0,
	}
	for _,exec := range executions {
		if exec.Function == "auth" {
			auth.TotalTime += exec.ExecutionTime
			auth.TotalExecutions++
		} else if exec.Function == "verify" {
			verify.TotalTime += exec.ExecutionTime
			verify.TotalExecutions++
		}
	}

	auth.AverageTime = strconv.FormatInt(time.Duration(int64(auth.TotalTime)/auth.TotalExecutions).Microseconds(), 10) + "µs"
	verify.AverageTime = strconv.FormatInt(time.Duration(int64(verify.TotalTime)/verify.TotalExecutions).Microseconds(), 10) + "µs"

	var stat = stat{
		AuthStat:   auth,
		VerifyStat: verify,
	}

	c.JSON(http.StatusOK, stat)
}

func getAuthByUsername(c *gin.Context) {
	start := time.Now()
	exec := execution{
		ExecutionTime: 0,
		Function:      "auth",
	}
	username := c.Param("username")

	var publicKey, err = ioutil.ReadFile("../../public.pem")
	if err != nil {
		fmt.Println("error in reading puk" + err.Error())
		c.String(http.StatusInternalServerError, err.Error())
		exec.ExecutionTime = time.Since(start)
		executions = append(executions, exec)
		return
	}

	var privateKey, err2 = ioutil.ReadFile("../../private.pem")
	if err2 != nil {
		fmt.Println("error in reading prk" + err2.Error())
		c.String(http.StatusInternalServerError, err2.Error())
		exec.ExecutionTime = time.Since(start)
		executions = append(executions, exec)
		return
	}

	jwtToken := NewJWT(privateKey, publicKey)

	tok, err3 := jwtToken.Create(time.Hour * 24, username)
	if err3 != nil {
		fmt.Println("error in creating token" + err3.Error())
		c.String(http.StatusInternalServerError, err3.Error())
		exec.ExecutionTime = time.Since(start)
		executions = append(executions, exec)
		return
	}

	c.SetCookie("token", tok, 86400, "/", "", false, true)
	c.String(http.StatusOK, string(publicKey))
	exec.ExecutionTime = time.Since(start)
	executions = append(executions, exec)
}

func verifyJWT(c *gin.Context) {
	start := time.Now()
	exec := execution{
		ExecutionTime: 0,
		Function:      "verify",
	}
	cookie,err := c.Cookie("token")
	if err != nil {
		fmt.Println("error reading cookie" + err.Error())
		c.String(http.StatusUnauthorized, "Cookie 'token' not set.")
		exec.ExecutionTime = time.Since(start)
		executions = append(executions, exec)
		return
	}

	var publicKey, err2 = ioutil.ReadFile("../../public.pem")
	if err2 != nil {
		fmt.Println("error in reading puk" + err2.Error())
		c.String(http.StatusInternalServerError, err2.Error())
		exec.ExecutionTime = time.Since(start)
		executions = append(executions, exec)
		return
	}

	var privateKey, err3 = ioutil.ReadFile("../../private.pem")
	if err3 != nil {
		fmt.Println("error in reading prk" + err3.Error())
		c.String(http.StatusInternalServerError, err3.Error())
		exec.ExecutionTime = time.Since(start)
		executions = append(executions, exec)
		return
	}

	jwtToken := NewJWT(privateKey, publicKey)

	username, err4 := jwtToken.Validate(cookie)
	if err4 != nil {
		fmt.Println("error in validating token" + err4.Error())
		c.String(http.StatusInternalServerError, err4.Error())
		exec.ExecutionTime = time.Since(start)
		executions = append(executions, exec)
		return
	}

	c.String(http.StatusOK, username.(string))
	exec.ExecutionTime = time.Since(start)
	executions = append(executions, exec)
}

func sendREADME(c *gin.Context){
	var readme, _ = ioutil.ReadFile("../../README.txt")
	c.String(http.StatusOK, string(readme))
}

type JWT struct {
	privateKey []byte
	publicKey  []byte
}

func NewJWT(privateKey []byte, publicKey []byte) JWT {
	return JWT{
		privateKey: privateKey,
		publicKey:  publicKey,
	}
}

func (j JWT) Create(ttl time.Duration, content interface{}) (string, error) {
	key, err := jwt.ParseRSAPrivateKeyFromPEMWithPassword(j.privateKey, "cloudflare")
	if err != nil {
		return "", fmt.Errorf("create: parse key: %w", err)
	}

	now := time.Now().UTC()

	claims := make(jwt.MapClaims)
	claims["sub"] = content             // Our custom data.
	claims["exp"] = now.Add(ttl).Unix() // The expiration time after which the token must be disregarded.
	claims["iat"] = now.Unix()          // The time at which the token was issued.
	claims["nbf"] = now.Unix()          // The time before which the token must be disregarded.

	token, err := jwt.NewWithClaims(jwt.SigningMethodRS256, claims).SignedString(key)
	if err != nil {
		return "", fmt.Errorf("create: sign token: %w", err)
	}

	return token, nil
}

func (j JWT) Validate(token string) (interface{}, error) {
	key, err := jwt.ParseRSAPublicKeyFromPEM(j.publicKey)
	if err != nil {
		return "", fmt.Errorf("validate: parse key: %w", err)
	}

	tok, err := jwt.Parse(token, func(jwtToken *jwt.Token) (interface{}, error) {
		if _, ok := jwtToken.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("unexpected method: %s", jwtToken.Header["alg"])
		}

		return key, nil
	})
	if err != nil {
		return nil, fmt.Errorf("validate: %w", err)
	}

	claims, ok := tok.Claims.(jwt.MapClaims)
	if !ok || !tok.Valid {
		return nil, fmt.Errorf("validate: invalid")
	}

	return claims["sub"], nil
}
