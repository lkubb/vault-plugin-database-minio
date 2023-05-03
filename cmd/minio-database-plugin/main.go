package main

import (
	"log"
	"os"

	"github.com/hashicorp/vault/sdk/database/dbplugin/v5"
	"github.com/lkubb/vault-plugin-database-minio"
)

func main() {
	err := Run()
	if err != nil {
		log.Println(err)
		os.Exit(1)
	}
}

func Run() error {
	dbplugin.ServeMultiplex(minio.New)

	return nil
}
