package main

import (
	"GoAuthService/internal/app"
	"GoAuthService/internal/database"
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

	app.MustStart()
	app.Logger.Info("application is running")
}

//TODO Под конец можно переписать миграции на sql скрипты которые будут запускаться с докер-компоуза и также под конец передалть на возможность читать из конфига
// 2. Сетап приложения модель -> (бд,logger,(gin,mux)сервер) + тест запуск
// 3. Написание маршрутов (4 эндпоинта)
// 4. Реализация сервисов по обработке маршрутов + реализация middleware
// 5. Описание документации swagger
