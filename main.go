package main

// vault "github.com/OIT-ADS/vault-go/vault"

import (
	"fmt"
	"os"

	"github.com/OIT-ADS-Web/vault-go/vault_go"
	"github.com/rs/zerolog/log"
)

func main() {
	log.Info().Msgf("Vault .env writer.\n")

	skipVault := (os.Getenv("SKIP_VAULT") == "1")

	if !skipVault {
		err, values := vault_go.Vault()
		if !err {
			// if .env does not exist, create it
			if _, err := os.Stat(".env"); err != nil {
				log.Info().Msgf(".env file does not exist. Will attempt to create.\n")
				f, ferr := os.Create(".env")
				if ferr != nil {
					log.Error().Msgf("Error creating .env file")
				} else {
					f.Write([]byte("# .env created by vault-go main().\n"))
					for j := 0; j < len(values); j++ {
						k := values[j]
						f.Write([]byte(fmt.Sprintf("%s='%s'\n", k.Name, k.Value)))
					}
					log.Info().Msgf("Vault information stored in .env file successfully.")
					defer f.Close()
				}

			} else {
				log.Info().Msgf(".env alredy exists -- NO UDPATES PERFORMED. To allow .env creation, delete .env before running vault-go.\n")
			}
		} else {
			log.Info().Msgf("An error occurred executing vault library.\n")
		}
	} else {
		log.Info().Msgf("SKIP_VAULT is true. Nothing to do.")
	}

}
