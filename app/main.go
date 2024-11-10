package main

import (
	"embed"
	"encoding/json"
	"log"
	"net/http"
	"os"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
)

//go:embed static index.html
var files embed.FS

var (
	tenantID     string
	clientID     string
	clientSecret string
)

type EmbedConfig struct {
	TokenId      string `json:"tokenId"`
	AccessToken  string `json:"accessToken"`
	TokenExpiry  string `json:"tokenExpiry"`
	ReportConfig string `json:"reportConfig"`
}

func init() {
	tenantID = os.Getenv("AZURE_TENANT_ID")
	clientID = os.Getenv("AZURE_CLIENT_ID")
	clientSecret = os.Getenv("AZURE_CLIENT_SECRET")

	if tenantID == "" || clientID == "" || clientSecret == "" {
		log.Fatal("Environment variables TENANT_ID, CLIENT_ID, or CLIENT_SECRET not set")
	}
}

func main() {
	mux := http.NewServeMux()
	mux.Handle("GET /", http.FileServer(http.FS(files)))

	mux.HandleFunc("GET /getembedinfo", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		cred, err := azidentity.NewDefaultAzureCredential(nil)
		if err != nil {
			log.Fatalf("failed to obtain a credential: %v", err)
		}

		token, err := cred.GetToken(r.Context(), policy.TokenRequestOptions{Scopes: []string{"https://analysis.windows.net/powerbi/api/.default"}})
		if err != nil {
			log.Fatalf("failed to get a token: %v", err)
		}

		embedConfig := EmbedConfig{
			TokenId:      token.Token,
			AccessToken:  "123456",
			TokenExpiry:  "123456",
			ReportConfig: "123456",
		}

		if err := json.NewEncoder(w).Encode(embedConfig); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	})

	err := http.ListenAndServe(":8080", mux)
	if err != nil {
		log.Fatal("ListenAndServe: ", err)
	}
}
