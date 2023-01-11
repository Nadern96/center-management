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
var otpCollection *mongo.Collection = db.GetCollection(db.Client, "otp")
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
		user.IsVerified, user.IsActive = false, false

		res, insertErr := userCollection.InsertOne(ctx, user)
		if insertErr != nil {
			log.Println(insertErr)
			c.JSON(http.StatusInternalServerError, gin.H{"error": insertErr.Error()})
			return
		}

		otp := utils.GenerateOTP()
		err = utils.SendEmail(*user.Email, otp)
		if err != nil {
			log.Println("send email: ", err)
		}

		otpObj := models.OTP{
			Otp:         otp,
			GeneratedAt: time.Now().Unix(),
			UserId:      user.ID.Hex(),
		}
		_, insertErr = otpCollection.InsertOne(ctx, otpObj)
		if insertErr != nil {
			log.Println("otp collection: ", insertErr)
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

		if !foundUser.IsVerified {
			log.Println("User is not verified")
			c.JSON(http.StatusInternalServerError, gin.H{"error": "User is not verified"})
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

func Verify() gin.HandlerFunc {
	return func(c *gin.Context) {
		id := c.Param("id")

		if id == "" {
			c.Header("Content-Type", "application/json")
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid argument"})
			c.Abort()
			return
		}
		var ctx, cancel = context.WithTimeout(context.Background(), 100*time.Second)
		defer cancel()

		var otp models.OTP
		if err := c.BindJSON(&otp); err != nil {
			log.Println(err)
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		err := otpCollection.FindOne(ctx, bson.M{"_id": id}).Decode(&otp)
		if err != nil {
			log.Println(err)
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid otp"})
			return
		}

		generatedAtTime := time.Unix(otp.GeneratedAt, 0)
		expiryTime := generatedAtTime.Add(time.Hour * 1)
		now := time.Now()

		if now.Unix() > expiryTime.Unix() {
			log.Println(err)
			c.JSON(http.StatusBadRequest, gin.H{"error": "Otp expired"})
			return
		}

		userId, _ := primitive.ObjectIDFromHex(id)
		filter := bson.M{"_id": userId}
		change := bson.M{"$set": bson.M{"isVerified": true}}
		_, err = userCollection.UpdateOne(ctx, filter, change)
		if err != nil {
			log.Println(err)
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}

		c.JSON(http.StatusOK, "User Successfully Verfied!")
	}
}
