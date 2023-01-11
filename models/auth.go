package models

import (
	"go.mongodb.org/mongo-driver/bson/primitive"
)

type User struct {
	ID              primitive.ObjectID `json:"_id" bson:"_id"`
	FirstName       *string            `json:"firstName,omitempty" bson:"firstName" validate:"required,min=2,max=30"`
	LastName        *string            `json:"lastName,omitempty" bson:"lastName" validate:"required,min=2,max=30"`
	Password        *string            `json:"password,omitempty" bson:"password" validate:"required,min=6" binding:"required"`
	PasswordConfirm *string            `json:"passwordConfirm,omitempty" bson:"passwordConfirm,omitempty"`
	Email           *string            `json:"email,omitempty" bson:"email" validate:"email,required" binding:"required"`
	Phone           *string            `json:"phone,omitempty" bson:"phone" validate:"required,min=6"`
	Token           *string            `json:"token,omitempty" bson:"token"`
	RefreshToken    *string            `json:"refreshToken,omitempty" bson:"refreshToken"`
	CreatedAt       int64              `json:"createdAt,omitempty" bson:"createdAt"`
	UpdatedAt       int64              `json:"updatedAt,omitempty" bson:"updatedAt"`
	IsActive        bool               `json:"isActive,omitempty" bson:"isActive"`
	IsVerified      bool               `json:"isVerified,omitempty" bson:"isVerified"`
}

type OTP struct {
	UserId      string `json:"_id" bson:"_id"`
	GeneratedAt int64  `json:"generatedAt" bson:"generatedAt"`
	Otp         string `json:"otp" bson:"otp"`
}

type ForgotPasswordInput struct {
	Email string `json:"email" binding:"required"`
}

type ResetPasswordInput struct {
	Password        string `json:"password" binding:"required"`
	PasswordConfirm string `json:"passwordConfirm" binding:"required"`
}
