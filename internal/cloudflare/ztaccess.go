package cloudflare

import (
	"context"
	"encoding/json"
	"net/url"

	"github.com/hnkNkm/flareadm/internal/errors"
	"github.com/hnkNkm/flareadm/internal/pagination"
)

// AccessApplicationTypeValues are the accepted Access application types.
var AccessApplicationTypeValues = []string{
	"self_hosted", "saas", "ssh", "vnc", "app_launcher", "warp", "biso",
	"bookmark", "dash_sso", "infrastructure", "rdp", "mcp", "mcp_portal", "proxy_endpoint",
}

// AccessPolicyDecisionValues are the accepted Access policy decisions.
var AccessPolicyDecisionValues = []string{"allow", "deny", "non_identity", "bypass"}

func accessAppsPath(accountID string, appID string, suffix string) string {
	p := "/accounts/" + url.PathEscape(accountID) + "/access/apps"
	if appID != "" {
		p += "/" + url.PathEscape(appID)
	}
	if suffix != "" {
		p += "/" + suffix
	}
	return p
}

func accessPoliciesPath(accountID, policyID string) string {
	p := "/accounts/" + url.PathEscape(accountID) + "/access/policies"
	if policyID != "" {
		p += "/" + url.PathEscape(policyID)
	}
	return p
}

func accessGroupsPath(accountID, groupID string) string {
	p := "/accounts/" + url.PathEscape(accountID) + "/access/groups"
	if groupID != "" {
		p += "/" + url.PathEscape(groupID)
	}
	return p
}

func accessIdPsPath(accountID, idpID string) string {
	p := "/accounts/" + url.PathEscape(accountID) + "/access/identity_providers"
	if idpID != "" {
		p += "/" + url.PathEscape(idpID)
	}
	return p
}

func accessTokensPath(accountID, tokenID, suffix string) string {
	p := "/accounts/" + url.PathEscape(accountID) + "/access/service_tokens"
	if tokenID != "" {
		p += "/" + url.PathEscape(tokenID)
	}
	if suffix != "" {
		p += "/" + suffix
	}
	return p
}

// accessList lists a page-paginated Access collection.
func accessList[T any](ctx context.Context, c *Client, path string, query url.Values, pol pagination.Policy) (*ListResult[T], error) {
	lq := listQuery{path: path, q: query, pol: pol}
	if c.raw {
		return rawList[T](ctx, c, lq)
	}
	return listTyped[T](ctx, c, lq)
}

// accessGet fetches one Access object.
func accessGet[T any](ctx context.Context, c *Client, path string) (*GetResult[T], error) {
	env, raw, err := c.requestJSON(ctx, "GET", path, nil, nil, "")
	if err != nil {
		return nil, err
	}
	var item T
	if err := decodeResult(env, &item); err != nil {
		return nil, errors.Wrap(errors.CodeUnclassified, "decoding Access response", err)
	}
	return &GetResult[T]{Item: item, RawBody: raw}, nil
}

// accessCreate posts an Access object.
func accessCreate[T any](ctx context.Context, c *Client, path string, body map[string]any) (*GetResult[T], error) {
	if len(body) == 0 {
		return nil, errors.Usage("nothing to send")
	}
	payload, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	env, raw, err := c.requestJSON(ctx, "POST", path, nil, payload, "application/json")
	if err != nil {
		return nil, err
	}
	var item T
	if err := decodeResult(env, &item); err != nil {
		return nil, errors.Wrap(errors.CodeUnclassified, "decoding Access response", err)
	}
	return &GetResult[T]{Item: item, RawBody: raw}, nil
}

// accessMergeUpdate applies overrides onto the current object (read-modify-PUT)
// so fields this CLI does not model are preserved.
func accessMergeUpdate[T any](ctx context.Context, c *Client, path string, overrides map[string]any) (*GetResult[T], error) {
	if len(overrides) == 0 {
		return nil, errors.Usage("nothing to update")
	}
	env, _, err := c.requestJSON(ctx, "GET", path, nil, nil, "")
	if err != nil {
		return nil, err
	}
	var current map[string]any
	if err := json.Unmarshal(env.Result, &current); err != nil {
		return nil, errors.Wrap(errors.CodeUnclassified, "decoding existing Access object", err)
	}
	for k, v := range overrides {
		current[k] = v
	}
	payload, err := json.Marshal(current)
	if err != nil {
		return nil, err
	}
	putEnv, raw, err := c.requestJSON(ctx, "PUT", path, nil, payload, "application/json")
	if err != nil {
		return nil, err
	}
	var item T
	if err := decodeResult(putEnv, &item); err != nil {
		return nil, errors.Wrap(errors.CodeUnclassified, "decoding Access response", err)
	}
	return &GetResult[T]{Item: item, RawBody: raw}, nil
}

func accessDelete(ctx context.Context, c *Client, path string) error {
	_, _, err := c.requestJSON(ctx, "DELETE", path, nil, nil, "")
	return err
}

// ---- applications ---------------------------------------------------------

// AccessApplicationQuery carries the supported application list filters.
type AccessApplicationQuery struct {
	Name   string
	Domain string
	Search string
	Exact  bool
	AUD    string
}

// ListAccessApplications lists Access applications (page pagination).
func (c *Client) ListAccessApplications(ctx context.Context, accountID string, q AccessApplicationQuery, pol pagination.Policy) (*ListResult[AccessApplication], error) {
	query := url.Values{}
	if q.Name != "" {
		query.Set("name", q.Name)
	}
	if q.Domain != "" {
		query.Set("domain", q.Domain)
	}
	if q.Search != "" {
		query.Set("search", q.Search)
	}
	if q.Exact {
		query.Set("exact", "true")
	}
	if q.AUD != "" {
		query.Set("aud", q.AUD)
	}
	return accessList[AccessApplication](ctx, c, accessAppsPath(accountID, "", ""), query, pol)
}

// GetAccessApplication fetches one Access application.
func (c *Client) GetAccessApplication(ctx context.Context, accountID, appID string) (*GetResult[AccessApplication], error) {
	return accessGet[AccessApplication](ctx, c, accessAppsPath(accountID, appID, ""))
}

// CreateAccessApplication creates an application (POST).
func (c *Client) CreateAccessApplication(ctx context.Context, accountID string, body map[string]any) (*GetResult[AccessApplication], error) {
	return accessCreate[AccessApplication](ctx, c, accessAppsPath(accountID, "", ""), body)
}

// UpdateAccessApplication patches an application by read-modify-PUT.
func (c *Client) UpdateAccessApplication(ctx context.Context, accountID, appID string, overrides map[string]any) (*GetResult[AccessApplication], error) {
	return accessMergeUpdate[AccessApplication](ctx, c, accessAppsPath(accountID, appID, ""), overrides)
}

// DeleteAccessApplication deletes an application (DELETE, idempotent).
func (c *Client) DeleteAccessApplication(ctx context.Context, accountID, appID string) error {
	return accessDelete(ctx, c, accessAppsPath(accountID, appID, ""))
}

// ---- application-scoped policies ------------------------------------------

// ListAccessApplicationPolicies lists an application's policies (page pagination).
func (c *Client) ListAccessApplicationPolicies(ctx context.Context, accountID, appID string, pol pagination.Policy) (*ListResult[AccessPolicy], error) {
	return accessList[AccessPolicy](ctx, c, accessAppsPath(accountID, appID, "policies"), url.Values{}, pol)
}

// GetAccessApplicationPolicy fetches one application policy.
func (c *Client) GetAccessApplicationPolicy(ctx context.Context, accountID, appID, policyID string) (*GetResult[AccessPolicy], error) {
	return accessGet[AccessPolicy](ctx, c, accessAppsPath(accountID, appID, "policies/"+url.PathEscape(policyID)))
}

// CreateAccessApplicationPolicy creates an application policy (POST).
func (c *Client) CreateAccessApplicationPolicy(ctx context.Context, accountID, appID string, body map[string]any) (*GetResult[AccessPolicy], error) {
	return accessCreate[AccessPolicy](ctx, c, accessAppsPath(accountID, appID, "policies"), body)
}

// UpdateAccessApplicationPolicy patches an application policy by read-modify-PUT.
func (c *Client) UpdateAccessApplicationPolicy(ctx context.Context, accountID, appID, policyID string, overrides map[string]any) (*GetResult[AccessPolicy], error) {
	return accessMergeUpdate[AccessPolicy](ctx, c, accessAppsPath(accountID, appID, "policies/"+url.PathEscape(policyID)), overrides)
}

// DeleteAccessApplicationPolicy deletes an application policy.
func (c *Client) DeleteAccessApplicationPolicy(ctx context.Context, accountID, appID, policyID string) error {
	return accessDelete(ctx, c, accessAppsPath(accountID, appID, "policies/"+url.PathEscape(policyID)))
}

// ---- reusable account-level policies --------------------------------------

// ListAccessPolicies lists reusable account-level policies (page pagination).
func (c *Client) ListAccessPolicies(ctx context.Context, accountID string, pol pagination.Policy) (*ListResult[AccessPolicy], error) {
	return accessList[AccessPolicy](ctx, c, accessPoliciesPath(accountID, ""), url.Values{}, pol)
}

// GetAccessPolicy fetches one reusable policy.
func (c *Client) GetAccessPolicy(ctx context.Context, accountID, policyID string) (*GetResult[AccessPolicy], error) {
	return accessGet[AccessPolicy](ctx, c, accessPoliciesPath(accountID, policyID))
}

// CreateAccessPolicy creates a reusable policy (POST).
func (c *Client) CreateAccessPolicy(ctx context.Context, accountID string, body map[string]any) (*GetResult[AccessPolicy], error) {
	return accessCreate[AccessPolicy](ctx, c, accessPoliciesPath(accountID, ""), body)
}

// UpdateAccessPolicy patches a reusable policy by read-modify-PUT.
func (c *Client) UpdateAccessPolicy(ctx context.Context, accountID, policyID string, overrides map[string]any) (*GetResult[AccessPolicy], error) {
	return accessMergeUpdate[AccessPolicy](ctx, c, accessPoliciesPath(accountID, policyID), overrides)
}

// DeleteAccessPolicy deletes a reusable policy.
func (c *Client) DeleteAccessPolicy(ctx context.Context, accountID, policyID string) error {
	return accessDelete(ctx, c, accessPoliciesPath(accountID, policyID))
}

// ---- groups ---------------------------------------------------------------

// AccessGroupQuery carries the supported group list filters.
type AccessGroupQuery struct {
	Name   string
	Search string
}

// ListAccessGroups lists Access groups (page pagination).
func (c *Client) ListAccessGroups(ctx context.Context, accountID string, q AccessGroupQuery, pol pagination.Policy) (*ListResult[AccessGroup], error) {
	query := url.Values{}
	if q.Name != "" {
		query.Set("name", q.Name)
	}
	if q.Search != "" {
		query.Set("search", q.Search)
	}
	return accessList[AccessGroup](ctx, c, accessGroupsPath(accountID, ""), query, pol)
}

// GetAccessGroup fetches one group.
func (c *Client) GetAccessGroup(ctx context.Context, accountID, groupID string) (*GetResult[AccessGroup], error) {
	return accessGet[AccessGroup](ctx, c, accessGroupsPath(accountID, groupID))
}

// CreateAccessGroup creates a group (POST).
func (c *Client) CreateAccessGroup(ctx context.Context, accountID string, body map[string]any) (*GetResult[AccessGroup], error) {
	return accessCreate[AccessGroup](ctx, c, accessGroupsPath(accountID, ""), body)
}

// UpdateAccessGroup patches a group by read-modify-PUT.
func (c *Client) UpdateAccessGroup(ctx context.Context, accountID, groupID string, overrides map[string]any) (*GetResult[AccessGroup], error) {
	return accessMergeUpdate[AccessGroup](ctx, c, accessGroupsPath(accountID, groupID), overrides)
}

// DeleteAccessGroup deletes a group.
func (c *Client) DeleteAccessGroup(ctx context.Context, accountID, groupID string) error {
	return accessDelete(ctx, c, accessGroupsPath(accountID, groupID))
}

// ---- identity providers ---------------------------------------------------

// ListIdentityProviders lists identity providers (page pagination).
func (c *Client) ListIdentityProviders(ctx context.Context, accountID string, scimEnabled string, pol pagination.Policy) (*ListResult[IdentityProvider], error) {
	query := url.Values{}
	if scimEnabled != "" {
		query.Set("scim_enabled", scimEnabled)
	}
	return accessList[IdentityProvider](ctx, c, accessIdPsPath(accountID, ""), query, pol)
}

// GetIdentityProvider fetches one identity provider.
func (c *Client) GetIdentityProvider(ctx context.Context, accountID, idpID string) (*GetResult[IdentityProvider], error) {
	return accessGet[IdentityProvider](ctx, c, accessIdPsPath(accountID, idpID))
}

// CreateIdentityProvider creates an identity provider (POST).
func (c *Client) CreateIdentityProvider(ctx context.Context, accountID string, body map[string]any) (*GetResult[IdentityProvider], error) {
	return accessCreate[IdentityProvider](ctx, c, accessIdPsPath(accountID, ""), body)
}

// UpdateIdentityProvider patches an identity provider by read-modify-PUT.
func (c *Client) UpdateIdentityProvider(ctx context.Context, accountID, idpID string, overrides map[string]any) (*GetResult[IdentityProvider], error) {
	return accessMergeUpdate[IdentityProvider](ctx, c, accessIdPsPath(accountID, idpID), overrides)
}

// DeleteIdentityProvider deletes an identity provider.
func (c *Client) DeleteIdentityProvider(ctx context.Context, accountID, idpID string) error {
	return accessDelete(ctx, c, accessIdPsPath(accountID, idpID))
}

// ---- service tokens -------------------------------------------------------

// AccessServiceTokenQuery carries the supported service token list filters.
type AccessServiceTokenQuery struct {
	Name   string
	Search string
}

// ListAccessServiceTokens lists service tokens (page pagination).
func (c *Client) ListAccessServiceTokens(ctx context.Context, accountID string, q AccessServiceTokenQuery, pol pagination.Policy) (*ListResult[AccessServiceToken], error) {
	query := url.Values{}
	if q.Name != "" {
		query.Set("name", q.Name)
	}
	if q.Search != "" {
		query.Set("search", q.Search)
	}
	return accessList[AccessServiceToken](ctx, c, accessTokensPath(accountID, "", ""), query, pol)
}

// GetAccessServiceToken fetches one service token (metadata only: the API
// returns the client secret only on create/rotate).
func (c *Client) GetAccessServiceToken(ctx context.Context, accountID, tokenID string) (*GetResult[AccessServiceToken], error) {
	return accessGet[AccessServiceToken](ctx, c, accessTokensPath(accountID, tokenID, ""))
}

// CreateAccessServiceToken creates a service token (POST). The response
// carries the client secret.
func (c *Client) CreateAccessServiceToken(ctx context.Context, accountID string, body map[string]any) (*GetResult[AccessServiceToken], error) {
	return accessCreate[AccessServiceToken](ctx, c, accessTokensPath(accountID, "", ""), body)
}

// UpdateAccessServiceToken patches a service token by read-modify-PUT.
func (c *Client) UpdateAccessServiceToken(ctx context.Context, accountID, tokenID string, overrides map[string]any) (*GetResult[AccessServiceToken], error) {
	return accessMergeUpdate[AccessServiceToken](ctx, c, accessTokensPath(accountID, tokenID, ""), overrides)
}

// DeleteAccessServiceToken deletes a service token.
func (c *Client) DeleteAccessServiceToken(ctx context.Context, accountID, tokenID string) error {
	return accessDelete(ctx, c, accessTokensPath(accountID, tokenID, ""))
}

// RotateAccessServiceToken rotates the client secret (POST). The response
// carries the new client secret.
func (c *Client) RotateAccessServiceToken(ctx context.Context, accountID, tokenID string, body map[string]any) (*GetResult[AccessServiceToken], error) {
	payload := []byte("{}")
	if len(body) > 0 {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		payload = b
	}
	env, raw, err := c.requestJSON(ctx, "POST", accessTokensPath(accountID, tokenID, "rotate"), nil, payload, "application/json")
	if err != nil {
		return nil, err
	}
	var item AccessServiceToken
	if err := decodeResult(env, &item); err != nil {
		return nil, errors.Wrap(errors.CodeUnclassified, "decoding service token response", err)
	}
	return &GetResult[AccessServiceToken]{Item: item, RawBody: raw}, nil
}
