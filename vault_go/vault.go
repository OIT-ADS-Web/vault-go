package vault_go

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"strings"

	// namsral/flag - use in client to set env from cmd line

	"github.com/rs/zerolog/log"
)

type config struct {
	ToEnvFile          bool
	SkipVault          bool
	PrefixSecrets      bool
	ProviderUrl        string
	VaultSecretPath    string
	VaultToken         string
	VaultRoleId        string
	VaultSecretId      string
	NamespaceTokenPath string
	NamespaceJWT       string
	NamespaceToken     string
	VaultFitzEndpoint  string
	VaultAuthTokenUri  string
	VaultOKDRole       string
	OutputPairs        []Pair
}

type approle struct {
	Auth auth `json:"auth"`
}

type authorization struct {
	LeaseId       string                 `json:"lease_id"`
	Renewable     bool                   `json:"renewable"`
	LeaseDuration int                    `json:"lease_duration"`
	Data          map[string]interface{} `json:"data"`
	Auth          auth                   `json:"auth"`
}

type auth struct {
	ClientToken string `json:"client_token"`
	//Policies      []string               `json:"policies"`
	//Metadata      map[string]interface{} `json:"metadata"`
	//LeaseDuration int                    `json:"lease_duration"`
	//Renewable     bool                   `json:"renewable"`
}

type secret struct {
	Version version `json:"data"`
}

type version struct {
	Data     map[string]interface{} `json:"data"`
	Metadata map[string]interface{} `json:"metadata"` // NOTE: not using
}

type Pair struct {
	Name  string
	Value string
}

func SkipVault(c config) bool {
	skip_or_exec := "Skipping"
	if !c.SkipVault {
		skip_or_exec = "Executing (SKIP_VAULT != 1)"
	}
	log.Info().Msgf("vault-go: %s vault configuration", skip_or_exec)
	return c.SkipVault
}

func UseDeveloperToken(c *config) bool {
	if c.VaultToken != "" {
		log.Info().Msgf("vault-go: Attempting to use developer token.")
		FetchSecrets(c)
		return true
	} else {
		log.Info().Msgf("vault-go: developer token empty and not used. Returning false to continue to next method.")
		return false
	}
}

func UseNamespaceToken(c *config) bool {
	c.VaultFitzEndpoint = os.Getenv("VAULT_FITZ_ENDPOINT")
	c.VaultOKDRole = os.Getenv("VAULT_OKD_ROLE")
	log.Info().Msgf("vault-go: Attempting to use OKD namespace token.")
	log.Info().Msgf("vault-go: NOTE: OKD namespace token approach has not been debugged yet.")

	hasInfo := c.NamespaceTokenPath != "" && c.VaultFitzEndpoint != "" && c.VaultOKDRole != ""
	if hasInfo {
		lines, err := os.ReadFile(c.NamespaceTokenPath)
		if err != nil {
			log.Error().Msgf("vault-go: error reading namespace jwt token for OKD: %+v\n", err)
			return false
		}

		c.NamespaceJWT = strings.TrimSpace(string(lines[:]))
		c.NamespaceToken, err = FetchTokenUsingNamespaceJwt(*c)
		if err == nil {
			FetchSecrets(c)
			return true
		} else {
			return false
		}

	} else {
		log.Error().Msgf("vault-go: missing environment info for VAULT_OKD_ROLE, VAULT_FITZ_ENDPOINT or VAULT_NAMESPACE_TOKEN_PATH")
	}
	return false
}

func UseApproleToken(c *config) bool {
	log.Info().Msgf("vault-go: Using app role token.")
	token, err := FetchTokenUsingRole(c)
	if err != nil {
		log.Info().Msgf("vault-go: Using app role token failed to obtain token.")
		return false
	}
	//log.Info().Msgf("token from app role: %s\n", token)

	c.VaultToken = token
	FetchSecrets(c)
	return true
}

type DocInfo struct {
	name        string
	is_required bool
	info        string
}

func ShowDocInfo(field_doc DocInfo) {
	outstr := fmt.Sprintf("%-25s", field_doc.name)
	if field_doc.is_required {
		outstr += fmt.Sprintf("%-14s", "REQUIRED")
	} else {
		outstr += fmt.Sprintf("%-14s", "not required")
	}
	outstr += fmt.Sprintf("\t%s\n\n", field_doc.info)
	log.Info().Msgf(outstr)
}

func EnvDoc() {
	log.Info().Msgf("Input environment variables")
	ShowDocInfo(DocInfo{"VAULT_PROVIDER_URL", true, "The base path for the vault REST service"})
	ShowDocInfo(DocInfo{"VAULT_SECRET_PATH", true, `Supply a comma separated list of paths to target vault json data elements.
	The data named by elements of the json(s) will be written to individual env values.
	Currently supports only simple key/value pairs in the json structure(s).`})
	ShowDocInfo(DocInfo{"VAULT_TOKEN", false, "Local developer token (to be used instead of ROLE_ID/SECRET_ID or OKD_ROLE)."})

}

func Vault() (bool, []Pair) {
	c := config{}

	c.SkipVault = (os.Getenv("SKIP_VAULT") == "1")
	if !c.SkipVault {
		c.PrefixSecrets = (os.Getenv("VAULT_PREFIX_SECRETS") == "1")
		c.ProviderUrl = os.Getenv("VAULT_PROVIDER_URL")
		if c.ProviderUrl == "" {
			EnvDoc()
			os.Exit(1)
		}
		c.VaultSecretPath = os.Getenv("VAULT_SECRET_PATH")
		if c.VaultSecretPath == "" {
			EnvDoc()
			os.Exit(1)
		}
		c.VaultToken = os.Getenv("VAULT_TOKEN")
		c.VaultRoleId = os.Getenv("VAULT_ROLE_ID")
		c.VaultSecretId = os.Getenv("VAULT_SECRET_ID")

		c.NamespaceTokenPath = os.Getenv("VAULT_NAMESPACE_TOKEN_PATH")

		c.VaultAuthTokenUri = GetVaultAuthTokenUri(c)
	}

	err := !(SkipVault(c) || UseNamespaceToken(&c) || UseApproleToken(&c) || UseDeveloperToken(&c))
	errstr := "success"
	if err {
		errstr = "failure"
	}
	log.Info().Msgf("vault() returning: %s\n", errstr)
	return err, c.OutputPairs
}

func FetchTokenUsingRole(c *config) (string, error) {
	vaultAddress := c.ProviderUrl
	roleID := c.VaultRoleId
	secretID := c.VaultSecretId
	endpoint := fmt.Sprintf("%s/%s", vaultAddress, "v1/auth/ess-web/approle/login")

	message := map[string]interface{}{
		"role_id":   roleID,
		"secret_id": secretID,
	}

	messageJson, err := json.Marshal(message)
	if err != nil {
		log.Error().Msgf("vault-go: Error creating role/secret message for vault token lookup: (%+v).", err)
		return "", err
	}

	resp, err := http.Post(endpoint, "application/json", bytes.NewBuffer(messageJson))
	if err != nil {
		log.Error().Msgf("vault-go: Error result from vault token lookup: (%+v).", err)
		return "", err
	}

	result := approle{}
	decodeErr := json.NewDecoder(resp.Body).Decode(&result)
	if decodeErr != nil {
		log.Error().Msgf("vault-go: Error decoding result from vault token lookup: (%+v).", err)
		return "", decodeErr
	}

	log.Info().Msgf("vault-go: vault token from role/secret successful.")
	return result.Auth.ClientToken, nil
}

func FetchSecrets(c *config) error {
	// fmt.Printf("VAULT_SECRET_PATH: %s\n", c.VaultSecretPath)
	// Split secret path by either , or ; (helm cli does not like commas)
	re := regexp.MustCompile(`[;,]`)
	paths := re.Split(c.VaultSecretPath, -1)
	for _, path := range paths {
		url := fmt.Sprintf("%s/v1/%s", c.ProviderUrl, strings.TrimSpace(path))
		log.Info().Msgf("vault-go: vault path: %s\n", url)
		client := &http.Client{}
		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			return err
		}

		req.Header.Set("X-Vault-Token", c.VaultToken)
		resp, err := client.Do(req)
		if err != nil {
			return err
		}

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			return err
		}
		// log.Info().Msgf("Vault secret response json: %+v\n", string(body)) // <-- WARNING
		secret := secret{}
		if err = json.Unmarshal(body, &secret); err != nil {
			log.Error().Msgf("vault-go: Unable to parse response from vault. The response was %s from vault.\n", resp.Status)
			return err
		} else {
			//log.Info().Msgf("secret data: %+v type: %+v", secret.Version.Data, reflect.TypeOf(secret.Version.Data))
			//log.Info().Msgf("secret data: %+v", secret.Version)
			if len(secret.Version.Data) != 0 {
				keys := make([]string, len(secret.Version.Data))
				i := 0
				for k := range secret.Version.Data {
					keys[i] = k

					v := secret.Version.Data[k].(string)

					// log.Info().Msgf("key: %+v, value: %s\n", keys[i], v) // <-- WARNING
					vault_name_components := strings.Split(path, "/")
					vault_name := vault_name_components[len(vault_name_components)-3]
					vault_var := vault_name_components[len(vault_name_components)-1]

					var env_var string

					if c.PrefixSecrets {
						env_var = fmt.Sprintf("%s_%s_%s", strings.ToUpper(vault_name), strings.ToUpper(vault_var), strings.ToUpper(k))
					} else {
						env_var = fmt.Sprintf("%s_%s", strings.ToUpper(vault_var), strings.ToUpper(k))
					}

					vault_var_path := fmt.Sprintf("%s/%s", path, k)
					log.Info().Msgf("vault-go: setting environment variable: %s to value from vault path: %s", env_var, vault_var_path)
					os.Setenv(env_var, v)
					c.OutputPairs = append(c.OutputPairs, Pair{env_var, v})
					i++
				}
			} else {
				log.Error().Msgf("vault-go: no secret data available for path: %s", path)
			}
		}
	}
	return nil
}

func GetVaultAuthTokenUri(c config) string {

	if c.VaultFitzEndpoint != "" && c.ProviderUrl != "" {
		return c.ProviderUrl + "/" + "v1/auth/global/" + c.VaultFitzEndpoint + "/login"
	}
	return ""

}

func FetchTokenUsingNamespaceJwt(c config) (string, error) {
	token := ""
	url := GetVaultAuthTokenUri(c)
	client := &http.Client{}
	reqBody, err := json.Marshal(map[string]string{
		"jwt":  c.NamespaceJWT,
		"role": c.VaultOKDRole,
	})

	if err != nil {
		return token, err
	}

	req, err := http.NewRequest("POST", url, bytes.NewBuffer(reqBody))
	if err != nil {
		return token, err
	}

	//req.Header.Set("X-Vault-Token", c.VaultToken)
	req.Header.Set("Content-Type", "application/json; charset=UTF-8")
	resp, err := client.Do(req)
	if err != nil {
		return token, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return token, err
	}

	authz := authorization{}
	if err = json.Unmarshal(body, &authz); err != nil {
		log.Error().Msgf("vault-go: resp parse error: %s. The response was %s from vault.\n", err, resp.Status)
		return token, err
	} else {
		token = authz.Auth.ClientToken
	}

	return token, nil
}
