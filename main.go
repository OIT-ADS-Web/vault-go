package main

// vault "github.com/OIT-ADS/vault-go/vault"

import (
	"fmt"
	"os"

	"github.com/OIT-ADS/vault-go/vault_go"
	"github.com/rs/zerolog/log"
)

func main() {
	fmt.Printf("Vault .env writer.\n")
	err, values := vault_go.Vault(true)
	if !err {
		// if .env does not exist, create it
		if _, err := os.Stat(".env"); err != nil {
			fmt.Printf(".env file does not exist.\n")
			f, ferr := os.Create(".env")
			if ferr != nil {
				log.Error().Msgf("Error creating .env file")
			} else {
				for j := 0; j < len(values); j++ {
					k := values[j]
					f.Write([]byte(fmt.Sprintf("export %s=%s\n", k.Name, k.Value)))
				}
				log.Info().Msgf("Vault information stored in .env file successfully.")
				defer f.Close()
			}

		} else {
			fmt.Printf(".env alredy exists -- NO UDPATES PERFORMED. To allow .env creation, delete .env before running vault-go.\n")
		}
	} else {
		fmt.Printf("An error occurred executing vault library.\n")
	}

}
