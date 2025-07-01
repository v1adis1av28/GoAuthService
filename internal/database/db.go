package database

import (
	"context"
	"fmt"
	"os"

	"github.com/jackc/pgx/v5"
)

type Db struct {
	DB_URL  string
	DB_CONN *pgx.Conn
}

func NewDB(db_url string) *Db {
	conn, err := pgx.Connect(context.Background(), db_url)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Unable tro connect to database")
		os.Exit(1)
	}
	return &Db{
		DB_URL:  db_url,
		DB_CONN: conn,
	}
}
