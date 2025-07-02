package app

import (
	"GoAuthService/internal/database"
	"GoAuthService/internal/handlers"
	"log/slog"
	"net/http"

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

func (a *App) MustStart(h *handlers.UserHandler) {
	a.Router.Use(func(c *gin.Context) {
		c.Writer.Header().Set("Access-Control-Allow-Origin", "*")
		c.Writer.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
		c.Writer.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		c.Writer.Header().Set("Access-Control-Allow-Credentials", "true")

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(http.StatusNoContent)
			return
		}

		c.Next()
	})
	if err := a.Run(h); err != nil {
		panic(err)
	}

}

func (app *App) Run(h *handlers.UserHandler) error {
	app.Logger.Info("Server is running on :8080")

	if err := app.SetupRoutes(h); err != nil {
		app.Logger.Error("Failed to setup server routes", "error", err)
		return err
	}

	app.Logger.Info("Server succesfully setup routes!")

	if err := app.Router.Run(); err != nil {
		app.Logger.Error("Failed to start server", "error", err)
		return err
	}
	return nil
}

func (app *App) SetupRoutes(h *handlers.UserHandler) error {
	//мб стоит добавить префикс /auth?
	//	app.Router.POST("/logout", handlers.Logout())
	app.Router.GET("/token", h.GetTokenPair)
	//	app.Router.POST("/update", handlers.UpdateTokens())
	//	app.Router.GET("/guid", handlers.GetUserGUID())

	return nil
}
