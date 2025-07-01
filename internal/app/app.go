package app

import (
	"GoAuthService/internal/database"
	"GoAuthService/internal/handlers"
	"log/slog"

	"github.com/gin-gonic/gin"
)

type App struct {
	Logger *slog.Logger
	DB     *database.Db
	Router *gin.Engine
}

func NewApp(logger *slog.Logger, db *database.Db) *App {
	router := gin.Default()
	return &App{
		Logger: logger,
		DB:     db,
		Router: router,
	}
}

func (a *App) MustStart() {
	if err := a.Run(); err != nil {
		panic(err)
	}
}

func (app *App) Run() error {
	app.Logger.Info("Server is running on :8080")
	if err := app.Router.Run(); err != nil {
		app.Logger.Error("Failed to start server", "error", err)
		return err
	}

	if err := app.SetupRoutes(); err != nil {
		app.Logger.Error("Failed to setup server routes", "error", err)
		return err
	}
	app.Logger.Info("Server succesfully setup routes!")
	return nil
}

func (app *App) SetupRoutes() error {
	app.Router.POST("/logout", handlers.Logout())
	app.Router.GET("/token", handlers.GetTokenPair())
	app.Router.POST("/update", handlers.UpdateTokens())
	app.Router.GET("/guid", handlers.GetUserGUID())

	return nil
}
