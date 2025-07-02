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
	// СлойБД -> промежуточный сервис с логикой -> хендлер
	// Репозиторий -> сервис -> хендлер

	userRepo := user.NewUserRepository(DB.DB_CONN)
	userService := auth.NewUserService(userRepo)
	userHandler := handlers.NewUserHandler(userService)

	app.MustStart(userHandler)
	app.Logger.Info("application is running")
}

//насчет хендлера с получение пары, там есть идея проверки на наличие в бд такого ююд если нет создавать новый и как нибудь в свагере при запуске приложения генерить рандомный
//TODO Под конец можно переписать миграции на sql скрипты которые будут запускаться с докер-компоуза и также под конец передалть на возможность читать из конфига
// 4. Реализация сервисов по обработке маршрутов + реализация middleware
// 5. Описание документации swagger
