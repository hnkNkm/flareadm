package cloudflare

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"mime/multipart"
	"net/textproto"
	"net/url"
	"path"
	"strconv"
	"strings"

	"github.com/hnkNkm/flareadm/internal/errors"
	"github.com/hnkNkm/flareadm/internal/pagination"
)

// WorkerFile is one module of a Worker upload.
type WorkerFile struct {
	Name    string
	Content []byte
}

// workerContentType picks the part content type from the module extension.
func workerContentType(name string) string {
	switch strings.ToLower(path.Ext(name)) {
	case ".js", ".mjs":
		return "application/javascript+module"
	case ".py":
		return "text/x-python"
	case ".txt":
		return "text/plain"
	case ".wasm":
		return "application/wasm"
	case ".map":
		return "application/source-map"
	default:
		return "application/octet-stream"
	}
}

func workerScriptsPath(accountID, script, suffix string) string {
	p := "/accounts/" + url.PathEscape(accountID) + "/workers/scripts"
	if script != "" {
		p += "/" + url.PathEscape(script)
	}
	if suffix != "" {
		p += "/" + suffix
	}
	return p
}

func workerZoneRoutesPath(zoneID, routeID string) string {
	p := "/zones/" + url.PathEscape(zoneID) + "/workers/routes"
	if routeID != "" {
		p += "/" + url.PathEscape(routeID)
	}
	return p
}

func workerDomainsPath(accountID, domainID string) string {
	p := "/accounts/" + url.PathEscape(accountID) + "/workers/domains"
	if domainID != "" {
		p += "/" + url.PathEscape(domainID)
	}
	return p
}

func pagesProjectsPath(accountID, project, suffix string) string {
	p := "/accounts/" + url.PathEscape(accountID) + "/pages/projects"
	if project != "" {
		p += "/" + url.PathEscape(project)
	}
	if suffix != "" {
		p += "/" + suffix
	}
	return p
}

// multipartWorkerBody builds the multipart upload body: the metadata object as a
// form field plus one part per module, named so metadata.main_module/body_part
// can reference it.
func multipartWorkerBody(metadata json.RawMessage, files []WorkerFile) ([]byte, string, error) {
	var buf bytes.Buffer
	writer := multipart.NewWriter(&buf)
	var compact bytes.Buffer
	if err := json.Compact(&compact, metadata); err != nil {
		return nil, "", errors.Wrap(errors.CodeUnclassified, "encoding upload metadata", err)
	}
	if err := writer.WriteField("metadata", compact.String()); err != nil {
		return nil, "", errors.Wrap(errors.CodeUnclassified, "encoding upload metadata", err)
	}
	for _, f := range files {
		header := make(textproto.MIMEHeader)
		header.Set("Content-Disposition", fmt.Sprintf(`form-data; name="%s"; filename="%s"`,
			escapeMultipartQuotes(f.Name), escapeMultipartQuotes(path.Base(f.Name))))
		header.Set("Content-Type", workerContentType(f.Name))
		part, err := writer.CreatePart(header)
		if err != nil {
			return nil, "", errors.Wrap(errors.CodeUnclassified, "encoding upload", err)
		}
		if _, err := part.Write(f.Content); err != nil {
			return nil, "", errors.Wrap(errors.CodeUnclassified, "encoding upload", err)
		}
	}
	if err := writer.Close(); err != nil {
		return nil, "", errors.Wrap(errors.CodeUnclassified, "encoding upload", err)
	}
	return buf.Bytes(), writer.FormDataContentType(), nil
}

func escapeMultipartQuotes(s string) string {
	return strings.NewReplacer("\\", "\\\\", `"`, "\\\"").Replace(s)
}

// ---- scripts --------------------------------------------------------------

// ListWorkerScripts lists scripts (the endpoint is not paginated).
func (c *Client) ListWorkerScripts(ctx context.Context, accountID, tag string, pol pagination.Policy) (*ListResult[WorkerScript], error) {
	query := url.Values{}
	if tag != "" {
		query.Set("tags", tag)
	}
	return singlePageList[WorkerScript](ctx, c, workerScriptsPath(accountID, "", ""), query, pol)
}

// UpdateWorkerScript uploads a script (PUT, multipart; creates it when absent).
func (c *Client) UpdateWorkerScript(ctx context.Context, accountID, script string, metadata json.RawMessage, files []WorkerFile, bindingsInherit string) (*GetResult[WorkerScript], error) {
	if len(metadata) == 0 {
		return nil, errors.Usage("--metadata is required")
	}
	if len(files) == 0 {
		return nil, errors.Usage("at least one --file NAME=@PATH is required")
	}
	body, contentType, err := multipartWorkerBody(metadata, files)
	if err != nil {
		return nil, err
	}
	query := url.Values{}
	if bindingsInherit != "" {
		query.Set("bindings_inherit", bindingsInherit)
	}
	env, raw, err := c.requestJSON(ctx, "PUT", workerScriptsPath(accountID, script, ""), query, body, contentType)
	if err != nil {
		return nil, err
	}
	var item WorkerScript
	if err := decodeResult(env, &item); err != nil {
		return nil, errors.Wrap(errors.CodeUnclassified, "decoding script response", err)
	}
	return &GetResult[WorkerScript]{Item: item, RawBody: raw}, nil
}

// DeleteWorkerScript deletes a script (DELETE, idempotent).
func (c *Client) DeleteWorkerScript(ctx context.Context, accountID, script string, force bool) error {
	query := url.Values{}
	if force {
		query.Set("force", "true")
	}
	_, _, err := c.requestJSON(ctx, "DELETE", workerScriptsPath(accountID, script, ""), query, nil, "")
	return err
}

// GetWorkerScriptContent fetches the deployed script content as raw bytes.
func (c *Client) GetWorkerScriptContent(ctx context.Context, accountID, script string) ([]byte, error) {
	return c.do(ctx, "GET", workerScriptsPath(accountID, script, "content/v2"), nil, nil, "")
}

// GetWorkerScriptSettings reads the script settings (bindings and metadata).
func (c *Client) GetWorkerScriptSettings(ctx context.Context, accountID, script string) (*GetResult[WorkerScriptSettings], error) {
	return accessGet[WorkerScriptSettings](ctx, c, workerScriptsPath(accountID, script, "settings"))
}

// UpdateWorkerScriptSettings merges overrides onto the current settings and
// PATCHes the result, so unmodeled fields survive.
func (c *Client) UpdateWorkerScriptSettings(ctx context.Context, accountID, script string, overrides map[string]any) (*GetResult[WorkerScriptSettings], error) {
	if len(overrides) == 0 {
		return nil, errors.Usage("nothing to update")
	}
	current, _, err := c.requestJSON(ctx, "GET", workerScriptsPath(accountID, script, "settings"), nil, nil, "")
	if err != nil {
		return nil, err
	}
	settings := map[string]any{}
	if err := json.Unmarshal(current.Result, &settings); err != nil {
		return nil, errors.Wrap(errors.CodeUnclassified, "decoding script settings", err)
	}
	for k, v := range overrides {
		settings[k] = v
	}
	payload, err := json.Marshal(map[string]any{"settings": settings})
	if err != nil {
		return nil, err
	}
	env, raw, err := c.requestJSON(ctx, "PATCH", workerScriptsPath(accountID, script, "settings"), nil, payload, "application/json")
	if err != nil {
		return nil, err
	}
	var item WorkerScriptSettings
	if err := decodeResult(env, &item); err != nil {
		return nil, errors.Wrap(errors.CodeUnclassified, "decoding script settings", err)
	}
	return &GetResult[WorkerScriptSettings]{Item: item, RawBody: raw}, nil
}

// ---- secrets --------------------------------------------------------------

// WorkerSecretValue is the write model of a secret. Text carries a credential
// and is never logged.
type WorkerSecretValue struct {
	Name   string
	Type   string
	Text   string
	KeyJWK json.RawMessage
	Usages []string
	Format string
}

func (v WorkerSecretValue) body() ([]byte, error) {
	if v.Name == "" {
		return nil, errors.Usage("--name is required")
	}
	secretType := v.Type
	if secretType == "" {
		secretType = "secret_text"
	}
	body := map[string]any{"name": v.Name, "type": secretType}
	if v.Text != "" {
		body["text"] = v.Text
	}
	if len(v.KeyJWK) > 0 {
		body["key_jwk"] = v.KeyJWK
	}
	if len(v.Usages) > 0 {
		body["usages"] = v.Usages
	}
	if v.Format != "" {
		body["format"] = v.Format
	}
	if v.Text == "" && len(v.KeyJWK) == 0 {
		return nil, errors.Usage("--text is required (or --key-jwk for an asymmetric key)")
	}
	return json.Marshal(body)
}

// ListWorkerSecrets lists the names of a script's secrets (not paginated).
func (c *Client) ListWorkerSecrets(ctx context.Context, accountID, script string, pol pagination.Policy) (*ListResult[WorkerSecret], error) {
	return singlePageList[WorkerSecret](ctx, c, workerScriptsPath(accountID, script, "secrets"), nil, pol)
}

// GetWorkerSecret reads one secret's metadata (never its value).
func (c *Client) GetWorkerSecret(ctx context.Context, accountID, script, name string) (*GetResult[WorkerSecret], error) {
	return accessGet[WorkerSecret](ctx, c, workerScriptsPath(accountID, script, "secrets/"+url.PathEscape(name)))
}

// CreateWorkerSecret creates or replaces a secret (PUT; the API has no separate
// update verb).
func (c *Client) CreateWorkerSecret(ctx context.Context, accountID, script string, v WorkerSecretValue) (*GetResult[WorkerSecret], error) {
	body, err := v.body()
	if err != nil {
		return nil, err
	}
	env, raw, err := c.requestJSON(ctx, "PUT", workerScriptsPath(accountID, script, "secrets"), nil, body, "application/json")
	if err != nil {
		return nil, err
	}
	var item WorkerSecret
	if err := decodeResult(env, &item); err != nil {
		return nil, errors.Wrap(errors.CodeUnclassified, "decoding secret response", err)
	}
	return &GetResult[WorkerSecret]{Item: item, RawBody: raw}, nil
}

// DeleteWorkerSecret deletes a secret (DELETE, idempotent).
func (c *Client) DeleteWorkerSecret(ctx context.Context, accountID, script, name string) error {
	_, _, err := c.requestJSON(ctx, "DELETE", workerScriptsPath(accountID, script, "secrets/"+url.PathEscape(name)), nil, nil, "")
	return err
}

// ---- versions -------------------------------------------------------------

// ListWorkerVersions lists script versions (page pagination).
func (c *Client) ListWorkerVersions(ctx context.Context, accountID, script string, deployable bool, pol pagination.Policy) (*ListResult[WorkerVersion], error) {
	query := url.Values{}
	if deployable {
		query.Set("deployable", "true")
	}
	return listTyped[WorkerVersion](ctx, c, listQuery{path: workerScriptsPath(accountID, script, "versions"), q: query, pol: pol})
}

// GetWorkerVersion reads one version.
func (c *Client) GetWorkerVersion(ctx context.Context, accountID, script, versionID string) (*GetResult[WorkerVersion], error) {
	return accessGet[WorkerVersion](ctx, c, workerScriptsPath(accountID, script, "versions/"+url.PathEscape(versionID)))
}

// CreateWorkerVersion uploads a new version (POST, multipart).
func (c *Client) CreateWorkerVersion(ctx context.Context, accountID, script string, metadata json.RawMessage, files []WorkerFile, bindingsInherit string) (*GetResult[WorkerVersion], error) {
	if len(metadata) == 0 {
		return nil, errors.Usage("--metadata is required")
	}
	if len(files) == 0 {
		return nil, errors.Usage("at least one --file NAME=@PATH is required")
	}
	body, contentType, err := multipartWorkerBody(metadata, files)
	if err != nil {
		return nil, err
	}
	query := url.Values{}
	if bindingsInherit != "" {
		query.Set("bindings_inherit", bindingsInherit)
	}
	env, raw, err := c.requestJSON(ctx, "POST", workerScriptsPath(accountID, script, "versions"), query, body, contentType)
	if err != nil {
		return nil, err
	}
	var item WorkerVersion
	if err := decodeResult(env, &item); err != nil {
		return nil, errors.Wrap(errors.CodeUnclassified, "decoding version response", err)
	}
	return &GetResult[WorkerVersion]{Item: item, RawBody: raw}, nil
}

// ---- deployments ----------------------------------------------------------

// ListWorkerDeployments lists a script's deployments. The response is a single
// object holding every deployment (no pagination).
func (c *Client) ListWorkerDeployments(ctx context.Context, accountID, script string, pol pagination.Policy) (*ListResult[WorkerDeployment], error) {
	if err := pol.Validate(); err != nil {
		return nil, errors.Usage("%s", err.Error())
	}
	env, raw, err := c.requestJSON(ctx, "GET", workerScriptsPath(accountID, script, "deployments"), nil, nil, "")
	if err != nil {
		return nil, err
	}
	if c.raw {
		return &ListResult[WorkerDeployment]{RawBody: raw}, nil
	}
	var page struct {
		Deployments []WorkerDeployment `json:"deployments"`
	}
	if err := json.Unmarshal(env.Result, &page); err != nil {
		return nil, errors.Wrap(errors.CodeUnclassified, "decoding deployment list", err)
	}
	items := page.Deployments
	if pol.MaxItems > 0 && len(items) > pol.MaxItems {
		items = items[:pol.MaxItems]
	}
	return &ListResult[WorkerDeployment]{Items: items}, nil
}

// GetWorkerDeployment reads one deployment.
func (c *Client) GetWorkerDeployment(ctx context.Context, accountID, script, deploymentID string) (*GetResult[WorkerDeployment], error) {
	return accessGet[WorkerDeployment](ctx, c, workerScriptsPath(accountID, script, "deployments/"+url.PathEscape(deploymentID)))
}

// CreateWorkerDeployment deploys versions (POST; the body is the deployment
// object, optionally forced past durability checks).
func (c *Client) CreateWorkerDeployment(ctx context.Context, accountID, script string, deployment map[string]any, force bool) (*GetResult[WorkerDeployment], error) {
	if len(deployment) == 0 {
		return nil, errors.Usage("nothing to deploy")
	}
	payload, err := json.Marshal(map[string]any{"deployment": deployment})
	if err != nil {
		return nil, err
	}
	query := url.Values{}
	if force {
		query.Set("force", "true")
	}
	env, raw, err := c.requestJSON(ctx, "POST", workerScriptsPath(accountID, script, "deployments"), query, payload, "application/json")
	if err != nil {
		return nil, err
	}
	var item WorkerDeployment
	if err := decodeResult(env, &item); err != nil {
		return nil, errors.Wrap(errors.CodeUnclassified, "decoding deployment response", err)
	}
	return &GetResult[WorkerDeployment]{Item: item, RawBody: raw}, nil
}

// DeleteWorkerDeployment deletes a deployment (DELETE, idempotent).
func (c *Client) DeleteWorkerDeployment(ctx context.Context, accountID, script, deploymentID string) error {
	_, _, err := c.requestJSON(ctx, "DELETE", workerScriptsPath(accountID, script, "deployments/"+url.PathEscape(deploymentID)), nil, nil, "")
	return err
}

// ---- schedules and subdomains ---------------------------------------------

// GetWorkerSchedule reads the cron schedule.
func (c *Client) GetWorkerSchedule(ctx context.Context, accountID, script string) (*GetResult[WorkerSchedule], error) {
	env, raw, err := c.requestJSON(ctx, "GET", workerScriptsPath(accountID, script, "schedules"), nil, nil, "")
	if err != nil {
		return nil, err
	}
	var page struct {
		Schedules []struct {
			Cron string `json:"cron"`
		} `json:"schedules"`
	}
	if err := json.Unmarshal(env.Result, &page); err != nil {
		return nil, errors.Wrap(errors.CodeUnclassified, "decoding schedule response", err)
	}
	item := WorkerSchedule{}
	for _, s := range page.Schedules {
		item.Crons = append(item.Crons, s.Cron)
	}
	return &GetResult[WorkerSchedule]{Item: item, RawBody: raw}, nil
}

// UpdateWorkerSchedule replaces the cron schedule (PUT; an empty list clears it).
func (c *Client) UpdateWorkerSchedule(ctx context.Context, accountID, script string, crons []string) (*GetResult[WorkerSchedule], error) {
	schedules := make([]map[string]string, 0, len(crons))
	for _, cron := range crons {
		schedules = append(schedules, map[string]string{"cron": cron})
	}
	payload, err := json.Marshal(schedules)
	if err != nil {
		return nil, err
	}
	env, raw, err := c.requestJSON(ctx, "PUT", workerScriptsPath(accountID, script, "schedules"), nil, payload, "application/json")
	if err != nil {
		return nil, err
	}
	var page struct {
		Schedules []struct {
			Cron string `json:"cron"`
		} `json:"schedules"`
	}
	if err := json.Unmarshal(env.Result, &page); err != nil {
		return nil, errors.Wrap(errors.CodeUnclassified, "decoding schedule response", err)
	}
	item := WorkerSchedule{}
	for _, s := range page.Schedules {
		item.Crons = append(item.Crons, s.Cron)
	}
	return &GetResult[WorkerSchedule]{Item: item, RawBody: raw}, nil
}

// GetWorkerScriptSubdomain reads a script's workers.dev state.
func (c *Client) GetWorkerScriptSubdomain(ctx context.Context, accountID, script string) (*GetResult[WorkerScriptSubdomain], error) {
	return accessGet[WorkerScriptSubdomain](ctx, c, workerScriptsPath(accountID, script, "subdomain"))
}

// EnableWorkerScriptSubdomain enables workers.dev (and optionally previews).
func (c *Client) EnableWorkerScriptSubdomain(ctx context.Context, accountID, script string, previews bool) (*GetResult[WorkerScriptSubdomain], error) {
	payload, err := json.Marshal(map[string]any{"enabled": true, "previews_enabled": previews})
	if err != nil {
		return nil, err
	}
	env, raw, err := c.requestJSON(ctx, "POST", workerScriptsPath(accountID, script, "subdomain"), nil, payload, "application/json")
	if err != nil {
		return nil, err
	}
	var item WorkerScriptSubdomain
	if err := decodeResult(env, &item); err != nil {
		return nil, errors.Wrap(errors.CodeUnclassified, "decoding subdomain response", err)
	}
	return &GetResult[WorkerScriptSubdomain]{Item: item, RawBody: raw}, nil
}

// DisableWorkerScriptSubdomain disables workers.dev for a script.
func (c *Client) DisableWorkerScriptSubdomain(ctx context.Context, accountID, script string) (*GetResult[WorkerScriptSubdomain], error) {
	env, raw, err := c.requestJSON(ctx, "DELETE", workerScriptsPath(accountID, script, "subdomain"), nil, nil, "")
	if err != nil {
		return nil, err
	}
	var item WorkerScriptSubdomain
	if err := decodeResult(env, &item); err != nil {
		return nil, errors.Wrap(errors.CodeUnclassified, "decoding subdomain response", err)
	}
	return &GetResult[WorkerScriptSubdomain]{Item: item, RawBody: raw}, nil
}

// ---- routes (zone scoped) -------------------------------------------------

// ListWorkerRoutes lists zone routes (not paginated).
func (c *Client) ListWorkerRoutes(ctx context.Context, zoneID string, pol pagination.Policy) (*ListResult[WorkerRoute], error) {
	return singlePageList[WorkerRoute](ctx, c, workerZoneRoutesPath(zoneID, ""), nil, pol)
}

// GetWorkerRoute reads one route.
func (c *Client) GetWorkerRoute(ctx context.Context, zoneID, routeID string) (*GetResult[WorkerRoute], error) {
	return accessGet[WorkerRoute](ctx, c, workerZoneRoutesPath(zoneID, routeID))
}

// CreateWorkerRoute creates a route (POST).
func (c *Client) CreateWorkerRoute(ctx context.Context, zoneID string, body map[string]any) (*GetResult[WorkerRoute], error) {
	return accessCreate[WorkerRoute](ctx, c, workerZoneRoutesPath(zoneID, ""), body)
}

// UpdateWorkerRoute patches a route by read-modify-PUT.
func (c *Client) UpdateWorkerRoute(ctx context.Context, zoneID, routeID string, overrides map[string]any) (*GetResult[WorkerRoute], error) {
	return accessMergeUpdate[WorkerRoute](ctx, c, workerZoneRoutesPath(zoneID, routeID), overrides)
}

// DeleteWorkerRoute deletes a route (DELETE, idempotent).
func (c *Client) DeleteWorkerRoute(ctx context.Context, zoneID, routeID string) error {
	return accessDelete(ctx, c, workerZoneRoutesPath(zoneID, routeID))
}

// ---- custom domains (account scoped) --------------------------------------

// WorkerDomainQuery carries the supported domain list filters.
type WorkerDomainQuery struct {
	Environment string
	Hostname    string
	Service     string
	ZoneID      string
	ZoneName    string
}

// ListWorkerDomains lists Workers custom domains (not paginated).
func (c *Client) ListWorkerDomains(ctx context.Context, accountID string, q WorkerDomainQuery, pol pagination.Policy) (*ListResult[WorkerDomain], error) {
	query := url.Values{}
	for _, item := range []struct{ key, value string }{
		{"environment", q.Environment}, {"hostname", q.Hostname}, {"service", q.Service},
		{"zone_id", q.ZoneID}, {"zone_name", q.ZoneName},
	} {
		if item.value != "" {
			query.Set(item.key, item.value)
		}
	}
	return singlePageList[WorkerDomain](ctx, c, workerDomainsPath(accountID, ""), query, pol)
}

// GetWorkerDomain reads one domain.
func (c *Client) GetWorkerDomain(ctx context.Context, accountID, domainID string) (*GetResult[WorkerDomain], error) {
	return accessGet[WorkerDomain](ctx, c, workerDomainsPath(accountID, domainID))
}

// AttachWorkerDomain attaches (or re-attaches) a domain with PUT.
func (c *Client) AttachWorkerDomain(ctx context.Context, accountID string, body map[string]any) (*GetResult[WorkerDomain], error) {
	if body["hostname"] == nil || body["service"] == nil {
		return nil, errors.Usage("--hostname and --service are required")
	}
	payload, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	env, raw, err := c.requestJSON(ctx, "PUT", workerDomainsPath(accountID, ""), nil, payload, "application/json")
	if err != nil {
		return nil, err
	}
	var item WorkerDomain
	if err := decodeResult(env, &item); err != nil {
		return nil, errors.Wrap(errors.CodeUnclassified, "decoding domain response", err)
	}
	return &GetResult[WorkerDomain]{Item: item, RawBody: raw}, nil
}

// DeleteWorkerDomain detaches a domain (DELETE, idempotent).
func (c *Client) DeleteWorkerDomain(ctx context.Context, accountID, domainID string) error {
	return accessDelete(ctx, c, workerDomainsPath(accountID, domainID))
}

// ---- account subdomain and settings ---------------------------------------

// GetWorkerSubdomain reads the account workers.dev subdomain.
func (c *Client) GetWorkerSubdomain(ctx context.Context, accountID string) (*GetResult[WorkerSubdomain], error) {
	return accessGet[WorkerSubdomain](ctx, c, "/accounts/"+url.PathEscape(accountID)+"/workers/subdomain")
}

// UpdateWorkerSubdomain sets the account workers.dev subdomain (PUT).
func (c *Client) UpdateWorkerSubdomain(ctx context.Context, accountID, name string) (*GetResult[WorkerSubdomain], error) {
	if name == "" {
		return nil, errors.Usage("--name is required")
	}
	payload, err := json.Marshal(map[string]any{"subdomain": name})
	if err != nil {
		return nil, err
	}
	env, raw, err := c.requestJSON(ctx, "PUT", "/accounts/"+url.PathEscape(accountID)+"/workers/subdomain", nil, payload, "application/json")
	if err != nil {
		return nil, err
	}
	var item WorkerSubdomain
	if err := decodeResult(env, &item); err != nil {
		return nil, errors.Wrap(errors.CodeUnclassified, "decoding subdomain response", err)
	}
	return &GetResult[WorkerSubdomain]{Item: item, RawBody: raw}, nil
}

// DeleteWorkerSubdomain removes the account workers.dev subdomain.
func (c *Client) DeleteWorkerSubdomain(ctx context.Context, accountID string) error {
	_, _, err := c.requestJSON(ctx, "DELETE", "/accounts/"+url.PathEscape(accountID)+"/workers/subdomain", nil, nil, "")
	return err
}

// GetWorkerAccountSettings reads the account-level Workers defaults.
func (c *Client) GetWorkerAccountSettings(ctx context.Context, accountID string) (*GetResult[WorkerAccountSettings], error) {
	return accessGet[WorkerAccountSettings](ctx, c, "/accounts/"+url.PathEscape(accountID)+"/workers/account-settings")
}

// UpdateWorkerAccountSettings merges overrides onto the current defaults and
// PUTs the result so unmodeled fields survive.
func (c *Client) UpdateWorkerAccountSettings(ctx context.Context, accountID string, overrides map[string]any) (*GetResult[WorkerAccountSettings], error) {
	return accessMergeUpdate[WorkerAccountSettings](ctx, c, "/accounts/"+url.PathEscape(accountID)+"/workers/account-settings", overrides)
}

// ---- Pages ----------------------------------------------------------------

// ListPagesProjects lists Pages projects (page pagination).
func (c *Client) ListPagesProjects(ctx context.Context, accountID string, pol pagination.Policy) (*ListResult[PagesProject], error) {
	return listTyped[PagesProject](ctx, c, listQuery{path: pagesProjectsPath(accountID, "", ""), q: url.Values{}, pol: pol})
}

// GetPagesProject reads one project.
func (c *Client) GetPagesProject(ctx context.Context, accountID, project string) (*GetResult[PagesProject], error) {
	return accessGet[PagesProject](ctx, c, pagesProjectsPath(accountID, project, ""))
}

// CreatePagesProject creates a project (POST).
func (c *Client) CreatePagesProject(ctx context.Context, accountID string, body map[string]any) (*GetResult[PagesProject], error) {
	if name, _ := body["name"].(string); name == "" {
		return nil, errors.Usage("--name is required")
	}
	if branch, _ := body["production_branch"].(string); branch == "" {
		return nil, errors.Usage("--production-branch is required")
	}
	return accessCreate[PagesProject](ctx, c, pagesProjectsPath(accountID, "", ""), body)
}

// UpdatePagesProject patches a project by read-modify-PATCH.
func (c *Client) UpdatePagesProject(ctx context.Context, accountID, project string, overrides map[string]any) (*GetResult[PagesProject], error) {
	return mergeUpdate[PagesProject](ctx, c, "PATCH", pagesProjectsPath(accountID, project, ""), overrides)
}

// DeletePagesProject deletes a project (DELETE, idempotent).
func (c *Client) DeletePagesProject(ctx context.Context, accountID, project string) error {
	return accessDelete(ctx, c, pagesProjectsPath(accountID, project, ""))
}

// PagesDeploymentQuery carries the supported deployment list filters.
type PagesDeploymentQuery struct {
	Environment string
}

// ListPagesDeployments lists a project's deployments (page pagination).
func (c *Client) ListPagesDeployments(ctx context.Context, accountID, project string, q PagesDeploymentQuery, pol pagination.Policy) (*ListResult[PagesDeployment], error) {
	query := url.Values{}
	if q.Environment != "" {
		query.Set("env", q.Environment)
	}
	return listTyped[PagesDeployment](ctx, c, listQuery{path: pagesProjectsPath(accountID, project, "deployments"), q: query, pol: pol})
}

// GetPagesDeployment reads one deployment.
func (c *Client) GetPagesDeployment(ctx context.Context, accountID, project, deploymentID string) (*GetResult[PagesDeployment], error) {
	return accessGet[PagesDeployment](ctx, c, pagesProjectsPath(accountID, project, "deployments/"+url.PathEscape(deploymentID)))
}

// DeletePagesDeployment deletes a deployment (DELETE, idempotent).
func (c *Client) DeletePagesDeployment(ctx context.Context, accountID, project, deploymentID string) error {
	return accessDelete(ctx, c, pagesProjectsPath(accountID, project, "deployments/"+url.PathEscape(deploymentID)))
}

// ListPagesProjectDomains lists a project's custom domains (not paginated).
func (c *Client) ListPagesProjectDomains(ctx context.Context, accountID, project string, pol pagination.Policy) (*ListResult[PagesProjectDomain], error) {
	return singlePageList[PagesProjectDomain](ctx, c, pagesProjectsPath(accountID, project, "domains"), nil, pol)
}

// GetPagesProjectDomain reads one project domain.
func (c *Client) GetPagesProjectDomain(ctx context.Context, accountID, project, domainName string) (*GetResult[PagesProjectDomain], error) {
	return accessGet[PagesProjectDomain](ctx, c, pagesProjectsPath(accountID, project, "domains/"+url.PathEscape(domainName)))
}

// CreatePagesProjectDomain attaches a custom domain (POST).
func (c *Client) CreatePagesProjectDomain(ctx context.Context, accountID, project, domainName string) (*GetResult[PagesProjectDomain], error) {
	if domainName == "" {
		return nil, errors.Usage("--name is required")
	}
	return accessCreate[PagesProjectDomain](ctx, c, pagesProjectsPath(accountID, project, "domains"), map[string]any{"name": domainName})
}

// RevalidatePagesProjectDomain re-runs validation for a domain (PATCH with an
// empty body: the endpoint exposes no updatable fields).
func (c *Client) RevalidatePagesProjectDomain(ctx context.Context, accountID, project, domainName string) (*GetResult[PagesProjectDomain], error) {
	env, raw, err := c.requestJSON(ctx, "PATCH", pagesProjectsPath(accountID, project, "domains/"+url.PathEscape(domainName)), nil, []byte("{}"), "application/json")
	if err != nil {
		return nil, err
	}
	var item PagesProjectDomain
	if err := decodeResult(env, &item); err != nil {
		return nil, errors.Wrap(errors.CodeUnclassified, "decoding domain response", err)
	}
	return &GetResult[PagesProjectDomain]{Item: item, RawBody: raw}, nil
}

// DeletePagesProjectDomain detaches a domain (DELETE, idempotent).
func (c *Client) DeletePagesProjectDomain(ctx context.Context, accountID, project, domainName string) error {
	return accessDelete(ctx, c, pagesProjectsPath(accountID, project, "domains/"+url.PathEscape(domainName)))
}

// strconv is used by generated paths in tests; keep the import honest.
var _ = strconv.Itoa
