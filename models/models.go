package models

import (
	"go.mongodb.org/mongo-driver/bson/primitive"
)

type User struct {
	ID           primitive.ObjectID `json:"_id" bson:"_id"`
	FirstName    *string            `json:"firstName" bson:"firstName" validate:"required,min=2,max=30"`
	LastName     *string            `json:"lastName" bson:"lastName" validate:"required,min=2,max=30"`
	Password     *string            `json:"password" bson:"password" validate:"required,min=6" binding:"required"`
	Email        *string            `json:"email" bson:"email" validate:"email,required" binding:"required"`
	Phone        *string            `json:"phone" bson:"phone" validate:"required,min=6"`
	Token        *string            `json:"token" bson:"token"`
	RefreshToken *string            `json:"refreshToken" bson:"refreshToken"`
	CreatedAt    int64              `json:"createdAt" bson:"createdAt"`
	UpdatedAt    int64              `json:"updatedAt" bson:"updatedAt"`
	IsActive     bool               `json:"isActive" bson:"isActive"`
	IsVerified   bool               `json:"isVerified" bson:"isVerified"`
}

type OTP struct {
	UserId      string `json:"_id" bson:"_id"`
	GeneratedAt int64  `json:"generatedAt" bson:"generatedAt"`
	Otp         string `json:"otp" bson:"otp"`
}
