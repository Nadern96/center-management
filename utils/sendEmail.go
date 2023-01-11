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

func SendVerificationEmail(toEmailAddress, otp string) error {
	subject := "Subject: Happiness Street - Verfiy you account\r\n\r\n"
	body := fmt.Sprintf("Use this otp: %v to verify your account, \nThis otp will expire in 1 hour \n\nThanks,\nHappiness Street", otp)

	return sendEmail(toEmailAddress, subject, body)
}

func SendResetPasswordEmail(toEmailAddress, resetToken string) error {
	subject := "Subject: Happiness Street - Your password reset token (valid for 10min)\r\n\r\n"
	port := os.Getenv("PORT")
	body := fmt.Sprintf("Use this link to reset your password: \nhttp://localhost:%v/api/auth/reset-password/%v\n\nThanks,\nHappiness Street", port, resetToken)
	return sendEmail(toEmailAddress, subject, body)
}

func sendEmail(toEmailAddress, subject, body string) error {
	from, password := EnvEmailCredentials()

	to := []string{toEmailAddress}
	host := "smtp.gmail.com"
	port := "587"
	address := host + ":" + port

	message := []byte(subject + body)

	auth := smtp.PlainAuth("", from, password, host)

	err := smtp.SendMail(address, auth, from, to, message)
	if err != nil {
		return err
	}
	return nil
}
