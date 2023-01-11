package utils

import (
	"fmt"
	"log"
	"net/smtp"
	"os"
	"time"

	"github.com/joho/godotenv"
)

func EnvEmailCredentials() (string, string) {
	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}

	return os.Getenv("SENDER_EMAIL"), os.Getenv("SENDER_PASSWORD")
}

func GenerateOTP() string {
	return fmt.Sprint(time.Now().Nanosecond())[:6]
}

func SendEmail(toEmailAddress, otp string) error {
	from, password := EnvEmailCredentials()

	to := []string{toEmailAddress}
	host := "smtp.gmail.com"
	port := "587"
	address := host + ":" + port

	subject := "Subject: Happiness Street - Verfiy you account\r\n\r\n"
	body := fmt.Sprintf("Use this otp: %v to verify your account, \nThis otp will expire in 1 hour \n\nThanks,\nHappiness Street", otp)

	message := []byte(subject + body)

	auth := smtp.PlainAuth("", from, password, host)

	err := smtp.SendMail(address, auth, from, to, message)
	if err != nil {
		return err
	}
	return nil
}
