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

//go:embed static template
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

type TemplateData struct {
	EmbedData EmbedData
	Error     string
}

// Optamos por fazer um cache do token de acesso do Entra ID. Ou seja, todos os
// clientes (requests) feitos à aplicação utilizarão o mesmo token e portanto o
// tempo de vida do token (aproximadamente de 1h) será compartilhado. É preciso
// estar ciente das implicações que isso pode trazer, uma vez que o tempo de
// vida do token de acesso do Entra ID é compartilhado com o tempo de vida do
// embed token do Power BI. Isso pode trazer implicações principalmente na
// experiência do usuário que pode estar com um cliente carregado no navegador
// com um token perto de expirar, ainda que tenha recém carregado um painel.
// Daí a implementação de uma lógica no lado do cliente apenas para renovar o
// embed token, suportado pela própria API do Power BI.
// Da documentação do Power BI:
// Por razões de segurança, o tempo de vida do token incorporado é definido pelo
// tempo de vida restante do token Microsoft Entra usado para chamar a API
// GenerateToken. Portanto, se você usar o mesmo token Microsoft Entra para
// gerar vários tokens incorporados, o tempo de vida dos tokens incorporados
// gerados será menor a cada chamada.
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

	// azidentity por padrão pega as credenciais de acesso das variáveis de
	// ambiente AZURE_CLIENT_SECRET, AZURE_TENANT_ID, AZURE_CLIENT_ID. Boa
	// prática é carregar essas credenciais do Azure Key Vault como variáveis de
	// ambiente no ambiente (VM, Container ou App Service) em que a aplicação
	// está rodando.
	credential, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		log.Printf("failed to obtain a credential: %v", err)
		return "", fmt.Errorf("failed to obtain a credential: %w", err)
	}

	token, err := credential.GetToken(ctx, policy.TokenRequestOptions{Scopes: []string{"https://analysis.windows.net/powerbi/api/.default"}})
	if err != nil {
		log.Printf("failed to get a token: %v", err)
		return "", fmt.Errorf("failed to get a token: %w", err)
	}

	e.token = token
	return token.Token, nil
}

func main() {
	app := &App{
		template:       template.Must(template.ParseFS(files, "template/*.html")),
		entraIdService: &EntraIdService{},
		httpClient:     &http.Client{Timeout: 30 * time.Second},
	}
	mux := http.NewServeMux()
	mux.Handle("GET /static/", http.FileServerFS(files))
	mux.HandleFunc("GET /", app.handleRoot)
	mux.HandleFunc("GET /w/{workspace}/r/{report}", app.handleEmbed)
	err := http.ListenAndServe(":8080", mux)
	if err != nil {
		log.Fatal("ListenAndServe: ", err)
	}
}

// Encapsula toda a lógica da aplicação e suas dependências
type App struct {
	template       *template.Template
	entraIdService *EntraIdService
	httpClient     *http.Client
}

func (app *App) handleRoot(w http.ResponseWriter, r *http.Request) {
	if err := app.template.ExecuteTemplate(w, "index.html", nil); err != nil {
		log.Printf("handleRoot failed to execute template: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}

func (app *App) handleEmbed(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	ctx := r.Context()
	workspaceID := r.PathValue("workspace")
	reportID := r.PathValue("report")
	report, err := app.fetchReport(ctx, workspaceID, reportID)
	if err != nil {
		log.Printf("handleEmbed failed to fetchReport %v", err)
		templateData := TemplateData{Error: err.Error()}
		if err := app.template.ExecuteTemplate(w, "index.html", templateData); err != nil {
			log.Printf("handleEmbed failed to execute template: %v", err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		}
		return
	}
	embedToken, err := app.fetchEmbedToken(ctx, report, workspaceID)
	if err != nil {
		log.Printf("handleEmbed failed to fetchEmbedToken %v", err)
		templateData := TemplateData{Error: err.Error()}
		if err := app.template.ExecuteTemplate(w, "index.html", templateData); err != nil {
			log.Printf("handleEmbed failed to execute template: %v", err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		}
		return
	}
	embedData := EmbedData{
		TokenId:     embedToken.TokenId,
		AccessToken: embedToken.Token,
		TokenExpiry: embedToken.Expiration,
		EmbedURL:    report.EmbedURL,
	}
	templateData := TemplateData{EmbedData: embedData}
	if err := app.template.ExecuteTemplate(w, "embed.html", templateData); err != nil {
		log.Printf("handleEmbed failed to execute template: %v", err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
	}
}

func (app *App) fetchReport(ctx context.Context, workspaceID, reportID string) (ReportResponse, error) {
	reportURL := fmt.Sprintf("https://api.powerbi.com/v1.0/myorg/groups/%s/reports/%s", workspaceID, reportID)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reportURL, nil)
	if err != nil {
		log.Printf("fetchReport failed to create report request: %v", err)
		return ReportResponse{}, fmt.Errorf("failed to create report request: %v", err)
	}
	token, err := app.entraIdService.getAccessToken(ctx)
	if err != nil {
		log.Printf("fetchReport failed to get access token: %v", err)
		return ReportResponse{}, fmt.Errorf("failed to get access token: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	res, err := app.httpClient.Do(req)
	if err != nil {
		log.Printf("fetchReport failed to fetch report: %v", err)
		return ReportResponse{}, fmt.Errorf("failed to fetch report: %w", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		log.Printf("fetchReport unexpected status: %v", res.Status)
		return ReportResponse{}, fmt.Errorf("unexpected status when fetching report: %s", res.Status)
	}
	var report ReportResponse
	if err := json.NewDecoder(res.Body).Decode(&report); err != nil {
		log.Printf("fetchReport failed to decode report response: %v", err)
		return ReportResponse{}, fmt.Errorf("failed to decode report response: %w", err)
	}
	return report, nil
}

func (app *App) fetchEmbedToken(ctx context.Context, report ReportResponse, workspaceID string) (EmbedTokenResponse, error) {
	embedTokenURL := "https://api.powerbi.com/v1.0/myorg/GenerateToken"
	embedTokenReq := EmbedTokenRequest{
		Datasets:         []map[string]string{{"id": report.DatasetID}},
		Reports:          []map[string]string{{"id": report.ReportID}},
		TargetWorkspaces: []map[string]string{{"id": workspaceID}},
	}
	embedTokenReqJSON, err := json.Marshal(embedTokenReq)
	if err != nil {
		log.Printf("fetchEmbedToken failed to marshal embed token request: %v", err)
		return EmbedTokenResponse{}, fmt.Errorf("failed to marshal embed token request: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, embedTokenURL, bytes.NewReader(embedTokenReqJSON))
	if err != nil {
		log.Printf("fetchEmbedToken failed to create embed token request: %v", err)
		return EmbedTokenResponse{}, fmt.Errorf("failed to create embed token request: %w", err)
	}
	token, err := app.entraIdService.getAccessToken(ctx)
	if err != nil {
		log.Printf("fetchEmbedToken failed to get access token: %v", err)
		return EmbedTokenResponse{}, fmt.Errorf("failed to get access token: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	res, err := app.httpClient.Do(req)
	if err != nil {
		log.Printf("fetchEmbedToken failed to fetch embed token: %v", err)
		return EmbedTokenResponse{}, fmt.Errorf("failed to fetch embed token: %w", err)
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		log.Printf("fetchEmbedToken unexpected status: %v", res.Status)
		return EmbedTokenResponse{}, fmt.Errorf("unexpected status when fetching embed token: %s", res.Status)
	}
	var embedToken EmbedTokenResponse
	if err := json.NewDecoder(res.Body).Decode(&embedToken); err != nil {
		log.Printf("fetchEmbedToken failed to decode embed token response: %v", err)
		return EmbedTokenResponse{}, fmt.Errorf("failed to decode embed token response: %w", err)
	}
	return embedToken, nil
}
