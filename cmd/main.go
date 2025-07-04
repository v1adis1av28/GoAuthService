package main

import (
	_ "GoAuthService/docs"
	"GoAuthService/internal/app"
	"GoAuthService/internal/config"
	"GoAuthService/internal/database"
	"GoAuthService/internal/handlers"
	"GoAuthService/internal/jwt"
	"GoAuthService/internal/repository/user"
	"GoAuthService/internal/service/auth"
	"context"
	"log/slog"
	"os"
)

// @title Go Auth Service
// @description Реализация части сервиса авторизации с использованием JWT, access/refresh токенов
// @host localhost:8080
// @BasePath /
// @securityDefinitions.apikey BearerAuth
// @in header
// @name Authorization
// @schemes http
func main() {
	cfg, err := config.Load()
	if err != nil {
		panic("Failed to load config: " + err.Error())
	}

	jwt.Init(cfg.JWT.Secret)

	DB := database.NewDB(cfg.DB.URL)
	defer DB.DB_CONN.Close(context.Background())

	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	app := app.NewApp(logger, DB)

	userRepo := user.NewUserRepository(DB.DB_CONN)
	userService := auth.NewUserService(userRepo)
	userHandler := handlers.NewUserHandler(userService)

	app.MustStart(userHandler)
	logger.Info("application is running", "port", cfg.Server.Port)
}
