package controllers

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"time"

	"regexp"

	"github.com/gin-gonic/gin"
	"github.com/go-playground/validator/v10"
	"github.com/nadern96/center-management/db"
	"github.com/nadern96/center-management/models"
	"github.com/nadern96/center-management/utils"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"golang.org/x/crypto/bcrypt"
)

var userCollection *mongo.Collection = db.GetCollection(db.Client, "user")
var validate = validator.New()

func hashPassword(password string) string {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	if err != nil {
		log.Panic(err)
	}
	return string(bytes)
}

func verifyPassword(userPass, givenPass string) (bool, string) {
	err := bcrypt.CompareHashAndPassword([]byte(givenPass), []byte(userPass))
	valid := true
	msg := ""

	if err != nil {
		msg = fmt.Sprintf("password is incorrect")
		valid = false
	}
	return valid, msg
}

func SignUp() gin.HandlerFunc {
	return func(c *gin.Context) {
		var ctx, cancel = context.WithTimeout(context.Background(), 100*time.Second)
		defer cancel()

		var user models.User
		if err := c.BindJSON(&user); err != nil {
			log.Println(err)
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		if validationErr := validate.Struct(&user); validationErr != nil {
			log.Println(validationErr)
			c.JSON(http.StatusBadRequest, gin.H{"error": validationErr})
			return
		}

		phoneRegex := regexp.MustCompile(`^01[0125][0-9]{8}$`)
		isValidPhone := phoneRegex.MatchString(*user.Phone)
		if !isValidPhone {
			log.Println("Invalid Phone number")
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid Phone number"})
			return
		}

		count, err := userCollection.CountDocuments(ctx, bson.M{"email": user.Email})
		if err != nil {
			log.Println(err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": err})
			return
		}
		if count > 0 {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "User already exists"})
			return
		}
		count, err = userCollection.CountDocuments(ctx, bson.M{"phone": user.Phone})
		if err != nil {
			log.Println(err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": err})
			return
		}
		if count > 0 {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "This phone number is already in use"})
			return
		}
		user.ID = primitive.NewObjectID()
		password := hashPassword(*user.Password)
		user.Password = &password
		user.CreatedAt = time.Now().Unix()
		user.UpdatedAt = time.Now().Unix()

		token, refreshToken, _ := utils.TokenGenerator(&user)
		user.Token = &token
		user.RefreshToken = &refreshToken

		res, insertErr := userCollection.InsertOne(ctx, user)
		if insertErr != nil {
			log.Println(insertErr)
			c.JSON(http.StatusInternalServerError, gin.H{"error": insertErr.Error()})
			return
		}
		c.JSON(http.StatusCreated, res)
	}
}

func SignIn() gin.HandlerFunc {
	return func(c *gin.Context) {
		var ctx, cancel = context.WithTimeout(context.Background(), 100*time.Second)
		defer cancel()

		var user models.User
		var foundUser models.User

		if err := c.BindJSON(&user); err != nil {
			log.Println(err)
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		err := userCollection.FindOne(ctx, bson.M{"email": user.Email}).Decode(&foundUser)
		if err != nil {
			log.Println(err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "email is incorrect"})
			return
		}

		passwordIsValid, msg := verifyPassword(*user.Password, *foundUser.Password)
		if !passwordIsValid {
			c.JSON(http.StatusInternalServerError, gin.H{"error": msg})
			return
		}

		token, refreshToken, _ := utils.TokenGenerator(&foundUser)
		utils.UpdateAllTokens(token, refreshToken, foundUser.ID)
		if err != nil {
			log.Println(err)
		}

		c.JSON(http.StatusFound, foundUser)
	}
}
