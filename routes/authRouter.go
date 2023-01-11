package routes

import (
	"github.com/gin-gonic/gin"
	"github.com/nadern96/center-management/controllers"
)

func AuthRoutes(routes *gin.Engine) {
	group := routes.Group("/api/auth")
	group.POST("/signup", controllers.SignUp())
	group.POST("/signin", controllers.SignIn())
	group.PUT("/verify/:id", controllers.Verify())
	group.POST("/forgot-password", controllers.ForgotPassword())
	group.PATCH("/reset-password/:resetToken", controllers.ResetPassword())
}
