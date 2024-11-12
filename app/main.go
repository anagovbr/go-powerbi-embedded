package main

import (
	"bytes"
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"sync"
	"text/template"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
)

//go:embed static template embed.html
var files embed.FS

// Retorno da API do Power BI
// https://learn.microsoft.com/en-us/rest/api/power-bi/reports/get-report-in-group
type ReportResponse struct {
	ReportID   string `json:"id"`
	ReportName string `json:"name"`
	EmbedURL   string `json:"embedUrl"`
	DatasetID  string `json:"datasetId"`
}

// Retorno da API do Power BI
// https://learn.microsoft.com/en-us/rest/api/power-bi/embed-token/generate-token#embedtoken
type EmbedTokenResponse struct {
	Token      string `json:"token"`
	TokenId    string `json:"tokenId"`
	Expiration string `json:"expiration"`
}

// Requisição para a API do Power BI
// https://learn.microsoft.com/en-us/rest/api/power-bi/embed-token/generate-token#generatetokenrequestv2
type EmbedTokenRequest struct {
	Datasets         []map[string]string `json:"datasets"`
	Reports          []map[string]string `json:"reports"`
	TargetWorkspaces []map[string]string `json:"targetWorkspaces"`
}

// Dados do report para serem enviados ao frontend
type EmbedData struct {
	TokenId     string `json:"tokenId"`
	AccessToken string `json:"accessToken"`
	TokenExpiry string `json:"tokenExpiry"`
	EmbedURL    string `json:"embedUrl"`
}

// For security reasons, the lifetime of the embed token is set to the
// remaining lifetime of the Microsoft Entra token used to call the
// GenerateToken API. Therefore, if you use the same Microsoft Entra
// token to generate several embed tokens, the lifetime of the
// generated embed tokens will be shorter with each call.
// https://learn.microsoft.com/en-us/power-bi/developer/embedded/generate-embed-token#considerations-and-limitations
type EntraIdService struct {
	token azcore.AccessToken
	mu    sync.Mutex
}

func (e *EntraIdService) getAccessToken(ctx context.Context) (string, error) {
	e.mu.Lock()
	defer e.mu.Unlock()

	if time.Now().Before(e.token.ExpiresOn) {
		return e.token.Token, nil
	}

	credential, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		return "", fmt.Errorf("failed to obtain a credential: %v", err)
	}

	token, err := credential.GetToken(ctx, policy.TokenRequestOptions{Scopes: []string{"https://analysis.windows.net/powerbi/api/.default"}})
	if err != nil {
		return "", fmt.Errorf("failed to get a token: %v", err)
	}

	e.token = token
	return token.Token, nil
}

func main() {
	httpClient := &http.Client{Timeout: 30 * time.Second}
	entraIdService := &EntraIdService{}
	mux := http.NewServeMux()
	mux.Handle("GET /static/", http.FileServerFS(files))

	mux.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
		templ, err := template.ParseFS(files, "template/*.html")
		if err != nil {
			log.Fatalf("failed to parse the template: %v", err)
		}
		if err := templ.ExecuteTemplate(w, "index.html", nil); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
	})

	mux.HandleFunc("GET /w/{workspace}/r/{report}", func(w http.ResponseWriter, r *http.Request) {
		// w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Type", "text/html")
		token, err := entraIdService.getAccessToken(r.Context())
		if err != nil {
			log.Fatalf("failed to get a token: %v", err)
		}

		workspaceID := r.PathValue("workspace")
		reportID := r.PathValue("report")
		reportURL := fmt.Sprintf("https://api.powerbi.com/v1.0/myorg/groups/%s/reports/%s", workspaceID, reportID)

		req, err := http.NewRequestWithContext(r.Context(), http.MethodGet, reportURL, nil)
		if err != nil {
			log.Fatalf("failed to create a request: %v", err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+token)
		res, err := httpClient.Do(req)
		if err != nil {
			log.Fatalf("failed to get a report: %v", err)
		}
		defer res.Body.Close()
		if res.StatusCode != http.StatusOK {
			log.Fatalf("unnexpected status: %v", res.Status)
		}
		var report ReportResponse = ReportResponse{}
		if err := json.NewDecoder(res.Body).Decode(&report); err != nil {
			log.Fatalf("failed to decode the response: %v", err)
		}

		embedTokenURL := "https://api.powerbi.com/v1.0/myorg/GenerateToken"
		embedTokenReq := EmbedTokenRequest{
			Datasets:         []map[string]string{{"id": report.DatasetID}},
			Reports:          []map[string]string{{"id": report.ReportID}},
			TargetWorkspaces: []map[string]string{{"id": workspaceID}},
		}
		embedTokenReqJSON, err := json.Marshal(embedTokenReq)
		if err != nil {
			log.Fatalf("failed to marshal the request: %v", err)
		}
		req, err = http.NewRequestWithContext(r.Context(), http.MethodPost, embedTokenURL, bytes.NewReader(embedTokenReqJSON))
		if err != nil {
			log.Fatalf("failed to create a request: %v", err)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+token)
		res, err = httpClient.Do(req)
		if err != nil {
			log.Fatalf("failed to get an embed token: %v", err)
		}
		defer res.Body.Close()
		if res.StatusCode != http.StatusOK {
			log.Fatalf("unnexpected status: %v", res.Status)
		}
		var embedToken EmbedTokenResponse = EmbedTokenResponse{}
		if err := json.NewDecoder(res.Body).Decode(&embedToken); err != nil {
			log.Fatalf("failed to decode the response: %v", err)
		}

		embedData := EmbedData{
			TokenId:     embedToken.TokenId,
			AccessToken: embedToken.Token,
			TokenExpiry: embedToken.Expiration,
			EmbedURL:    report.EmbedURL,
		}
		_ = embedData
		templ, err := template.ParseFS(files, "template/*.html")
		if err != nil {
			log.Fatalf("failed to parse the template: %v", err)
		}
		if err := templ.ExecuteTemplate(w, "embed.html", embedData); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}

		// if err := json.NewEncoder(w).Encode(embedData); err != nil {
		// 	http.Error(w, err.Error(), http.StatusInternalServerError)
		// }
	})

	err := http.ListenAndServe(":8080", mux)
	if err != nil {
		log.Fatal("ListenAndServe: ", err)
	}
}
