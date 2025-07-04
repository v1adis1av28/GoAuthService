package main

import (
	"GoAuthService/internal/app"
	"GoAuthService/internal/database"
	"GoAuthService/internal/handlers"
	"GoAuthService/internal/repository/user"
	"GoAuthService/internal/service/auth"
	"context"
	"log/slog"
	"os"

	"github.com/joho/godotenv"
)

func init() {
	err := godotenv.Load()
	if err != nil {
		panic("Cannot find env file")
	}
}

func main() {

	DB := database.NewDB(os.Getenv("DB_URL"))
	defer DB.DB_CONN.Close(context.Background())

	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	app := app.NewApp(logger, DB)

	userRepo := user.NewUserRepository(DB.DB_CONN)
	userService := auth.NewUserService(userRepo)
	userHandler := handlers.NewUserHandler(userService)

	app.MustStart(userHandler)
	app.Logger.Info("application is running")
}

// 5. Описание документации swagger
