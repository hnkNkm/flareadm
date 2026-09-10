// Package cloudflare implements FlareADM's service layer against the
// Cloudflare REST API. It is the only package that talks to the
// cloudflare-go SDK; command-layer code depends exclusively on the
// normalized models in this package and never on generated SDK types.
//
// The SDK client (github.com/cloudflare/cloudflare-go/v7) is used as the
// authenticated transport: FlareADM issues every request — typed service
// calls as well as the `api request` escape hatch — through the SDK's
// Execute layer so authentication, base URL, timeouts, retry middleware and
// error normalization stay centralized behind the adapter.
package cloudflare

import "encoding/json"

// Account is the normalized account model (GET /accounts, GET /accounts/{id}).
type Account struct {
	ID        string `json:"id" yaml:"id"`
	Name      string `json:"name" yaml:"name"`
	Type      string `json:"type,omitempty" yaml:"type,omitempty"`
	CreatedOn string `json:"created_on,omitempty" yaml:"created_on,omitempty"`
}

// Zone is the normalized zone model.
type Zone struct {
	ID                  string   `json:"id" yaml:"id"`
	Name                string   `json:"name" yaml:"name"`
	Status              string   `json:"status" yaml:"status"`
	Paused              bool     `json:"paused" yaml:"paused"`
	Type                string   `json:"type,omitempty" yaml:"type,omitempty"`
	AccountID           string   `json:"account_id,omitempty" yaml:"account_id,omitempty"`
	AccountName         string   `json:"account_name,omitempty" yaml:"account_name,omitempty"`
	NameServers         []string `json:"name_servers,omitempty" yaml:"name_servers,omitempty"`
	OriginalNameServers []string `json:"original_name_servers,omitempty" yaml:"original_name_servers,omitempty"`
	CreatedOn           string   `json:"created_on,omitempty" yaml:"created_on,omitempty"`
	ModifiedOn          string   `json:"modified_on,omitempty" yaml:"modified_on,omitempty"`
}

// DNSRecord is the normalized DNS record model. Data-only record types
// (CAA, SRV, ...) carry their payload in Data as raw JSON and have an empty
// Content field.
type DNSRecord struct {
	ID         string          `json:"id" yaml:"id"`
	ZoneID     string          `json:"zone_id,omitempty" yaml:"zone_id,omitempty"`
	ZoneName   string          `json:"zone_name,omitempty" yaml:"zone_name,omitempty"`
	Name       string          `json:"name" yaml:"name"`
	Type       string          `json:"type" yaml:"type"`
	Content    string          `json:"content,omitempty" yaml:"content,omitempty"`
	TTL        float64         `json:"ttl" yaml:"ttl"`
	Proxied    bool            `json:"proxied" yaml:"proxied"`
	Proxiable  bool            `json:"proxiable,omitempty" yaml:"proxiable,omitempty"`
	Priority   float64         `json:"priority,omitempty" yaml:"priority,omitempty"`
	Comment    string          `json:"comment,omitempty" yaml:"comment,omitempty"`
	Tags       []string        `json:"tags,omitempty" yaml:"tags,omitempty"`
	Data       json.RawMessage `json:"data,omitempty" yaml:"-"`
	CreatedOn  string          `json:"created_on,omitempty" yaml:"created_on,omitempty"`
	ModifiedOn string          `json:"modified_on,omitempty" yaml:"modified_on,omitempty"`
}

// DNSSEC is the normalized DNSSEC status model.
type DNSSEC struct {
	Status     string         `json:"status" yaml:"status"`
	Flags      float64        `json:"flags,omitempty" yaml:"flags,omitempty"`
	Algorithm  string         `json:"algorithm,omitempty" yaml:"algorithm,omitempty"`
	KeyType    string         `json:"key_type,omitempty" yaml:"key_type,omitempty"`
	Digests    []DNSSECDigest `json:"digests,omitempty" yaml:"digests,omitempty"`
	DS         string         `json:"ds,omitempty" yaml:"ds,omitempty"`
	ModifiedOn string         `json:"modified_on,omitempty" yaml:"modified_on,omitempty"`
}

// DNSSECDigest is one DNSSEC digest entry.
type DNSSECDigest struct {
	Type      string `json:"type" yaml:"type"`
	Algorithm string `json:"algorithm" yaml:"algorithm"`
	Digest    string `json:"digest" yaml:"digest"`
}

// PurgeResult is the normalized cache purge result.
type PurgeResult struct {
	ID string `json:"id" yaml:"id"`
}

// Verification is the normalized token verification result
// (GET /user/tokens/verify).
type Verification struct {
	ID     string `json:"id" yaml:"id"`
	Status string `json:"status" yaml:"status"`
}

// ImportResult is the normalized DNS record import summary.
type ImportResult struct {
	RecsAdded          float64 `json:"recs_added" yaml:"recs_added"`
	TotalRecordsParsed float64 `json:"total_records_parsed" yaml:"total_records_parsed"`
}

// ListResult carries the outcome of a list-style service call. Raw mode is
// active when RawBody is non-empty; callers print RawBody verbatim instead
// of rendering Items.
type ListResult[T any] struct {
	Items   []T
	RawBody []byte
}

// GetResult carries the outcome of a single-object service call.
type GetResult[T any] struct {
	Item    T
	RawBody []byte
}

// envErr mirrors one entry of the Cloudflare "errors" array.
type envErr struct {
	Code    int64  `json:"code"`
	Message string `json:"message"`
}

// envelope mirrors the top-level Cloudflare API response envelope.
type envelope struct {
	Success    bool              `json:"success"`
	Errors     []envErr          `json:"errors"`
	Messages   []json.RawMessage `json:"messages"`
	Result     json.RawMessage   `json:"result"`
	ResultInfo json.RawMessage   `json:"result_info"`
}

// cursorInfo decodes cursor-pagination metadata (result_info.cursor or the
// newer result_info.cursors.after form).
type cursorInfo struct {
	Count   int64  `json:"count"`
	Cursor  string `json:"cursor"`
	PerPage int64  `json:"per_page"`
	Cursors struct {
		After  string `json:"after"`
		Before string `json:"before"`
	} `json:"cursors"`
}

// nextCursor extracts the pagination cursor from raw result_info, accepting
// both cursor shapes.
func nextCursor(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var info cursorInfo
	if err := json.Unmarshal(raw, &info); err != nil {
		return ""
	}
	if info.Cursor != "" {
		return info.Cursor
	}
	return info.Cursors.After
}

// resultInfo mirrors result_info for v4 page pagination.
type resultInfo struct {
	Page       int64 `json:"page"`
	PerPage    int64 `json:"per_page"`
	Count      int64 `json:"count"`
	TotalCount int64 `json:"total_count"`
	TotalPages int64 `json:"total_pages"`
}

// ---- v0.2: zone SSL/TLS and certificates ---------------------------------

// SSLSetting is one zone SSL/TLS setting (GET/PATCH
// /zones/{zone}/settings/{setting_id}). Value is rendered as its textual
// form ("full", "1.2", "on", ...).
type SSLSetting struct {
	ID         string `json:"id" yaml:"id"`
	Value      string `json:"value" yaml:"value"`
	Editable   bool   `json:"editable" yaml:"editable"`
	ModifiedOn string `json:"modified_on,omitempty" yaml:"modified_on,omitempty"`
}

// UniversalSSL is the zone Universal SSL setting.
type UniversalSSL struct {
	Enabled bool `json:"enabled" yaml:"enabled"`
}

// CertificatePackCertificate is one certificate inside a certificate pack.
type CertificatePackCertificate struct {
	ID           string   `json:"id" yaml:"id"`
	Status       string   `json:"status" yaml:"status"`
	Hosts        []string `json:"hosts,omitempty" yaml:"hosts,omitempty"`
	Issuer       string   `json:"issuer,omitempty" yaml:"issuer,omitempty"`
	BundleMethod string   `json:"bundle_method,omitempty" yaml:"bundle_method,omitempty"`
	ExpiresOn    string   `json:"expires_on,omitempty" yaml:"expires_on,omitempty"`
	ModifiedOn   string   `json:"modified_on,omitempty" yaml:"modified_on,omitempty"`
}

// CertificatePack is a zone SSL certificate pack.
type CertificatePack struct {
	ID                   string                       `json:"id" yaml:"id"`
	Type                 string                       `json:"type" yaml:"type"`
	Status               string                       `json:"status" yaml:"status"`
	Hosts                []string                     `json:"hosts,omitempty" yaml:"hosts,omitempty"`
	CertificateAuthority string                       `json:"certificate_authority,omitempty" yaml:"certificate_authority,omitempty"`
	PrimaryCertificate   string                       `json:"primary_certificate,omitempty" yaml:"primary_certificate,omitempty"`
	Certificates         []CertificatePackCertificate `json:"certificates,omitempty" yaml:"certificates,omitempty"`
}

// Certificate is a zone custom certificate (GET/POST/DELETE
// /zones/{zone}/certificates).
type Certificate struct {
	ID                 string   `json:"id" yaml:"id"`
	ZoneID             string   `json:"zone_id,omitempty" yaml:"zone_id,omitempty"`
	Status             string   `json:"status" yaml:"status"`
	BundleMethod       string   `json:"bundle_method,omitempty" yaml:"bundle_method,omitempty"`
	Hosts              []string `json:"hosts,omitempty" yaml:"hosts,omitempty"`
	Issuer             string   `json:"issuer,omitempty" yaml:"issuer,omitempty"`
	Priority           float64  `json:"priority,omitempty" yaml:"priority,omitempty"`
	ExpiresOn          string   `json:"expires_on,omitempty" yaml:"expires_on,omitempty"`
	UploadedOn         string   `json:"uploaded_on,omitempty" yaml:"uploaded_on,omitempty"`
	ModifiedOn         string   `json:"modified_on,omitempty" yaml:"modified_on,omitempty"`
	PolicyRestrictions string   `json:"policy_restrictions,omitempty" yaml:"policy_restrictions,omitempty"`
}

// ---- v0.3: R2, KV and legacy page rules ----------------------------------

// R2Bucket is the normalized R2 bucket model.
type R2Bucket struct {
	Name         string `json:"name" yaml:"name"`
	Location     string `json:"location,omitempty" yaml:"location,omitempty"`
	StorageClass string `json:"storage_class,omitempty" yaml:"storage_class,omitempty"`
	Jurisdiction string `json:"jurisdiction,omitempty" yaml:"jurisdiction,omitempty"`
	CreationDate string `json:"creation_date,omitempty" yaml:"creation_date,omitempty"`
}

// KVNamespace is the normalized Workers KV namespace model.
type KVNamespace struct {
	ID                  string `json:"id" yaml:"id"`
	Title               string `json:"title" yaml:"title"`
	Jurisdiction        string `json:"jurisdiction,omitempty" yaml:"jurisdiction,omitempty"`
	SupportsURLEncoding bool   `json:"supports_url_encoding,omitempty" yaml:"supports_url_encoding,omitempty"`
}

// KVKey is the normalized KV key metadata (values are never included).
type KVKey struct {
	Name       string          `json:"name" yaml:"name"`
	Expiration float64         `json:"expiration,omitempty" yaml:"expiration,omitempty"`
	Metadata   json.RawMessage `json:"metadata,omitempty" yaml:"metadata,omitempty"`
}

// PageRule is the normalized legacy page rule model. Targets and Actions
// are kept as raw JSON so unknown target/action shapes survive round trips.
type PageRule struct {
	ID         string          `json:"id" yaml:"id"`
	Status     string          `json:"status" yaml:"status"`
	Priority   int64           `json:"priority" yaml:"priority"`
	Targets    json.RawMessage `json:"targets" yaml:"targets"`
	Actions    json.RawMessage `json:"actions" yaml:"actions"`
	CreatedOn  string          `json:"created_on,omitempty" yaml:"created_on,omitempty"`
	ModifiedOn string          `json:"modified_on,omitempty" yaml:"modified_on,omitempty"`
}

// ---- v0.3 slice 2: D1 and Queues -----------------------------------------

// D1Database is the normalized D1 database model.
type D1Database struct {
	UUID            string          `json:"uuid" yaml:"uuid"`
	Name            string          `json:"name" yaml:"name"`
	Version         string          `json:"version,omitempty" yaml:"version,omitempty"`
	NumTables       float64         `json:"num_tables,omitempty" yaml:"num_tables,omitempty"`
	FileSize        float64         `json:"file_size,omitempty" yaml:"file_size,omitempty"`
	Jurisdiction    string          `json:"jurisdiction,omitempty" yaml:"jurisdiction,omitempty"`
	ReadReplication json.RawMessage `json:"read_replication,omitempty" yaml:"read_replication,omitempty"`
	CreatedAt       string          `json:"created_at,omitempty" yaml:"created_at,omitempty"`
}

// D1StatementResult is one statement result of a D1 query.
type D1StatementResult struct {
	Success bool             `json:"success" yaml:"success"`
	Results []map[string]any `json:"results,omitempty" yaml:"results,omitempty"`
	Meta    *D1Meta          `json:"meta,omitempty" yaml:"meta,omitempty"`
}

// D1Meta is the per-statement execution metadata.
type D1Meta struct {
	ChangedDB       bool    `json:"changed_db,omitempty" yaml:"changed_db,omitempty"`
	Changes         float64 `json:"changes,omitempty" yaml:"changes,omitempty"`
	Duration        float64 `json:"duration,omitempty" yaml:"duration,omitempty"`
	LastRowID       float64 `json:"last_row_id,omitempty" yaml:"last_row_id,omitempty"`
	RowsRead        float64 `json:"rows_read,omitempty" yaml:"rows_read,omitempty"`
	RowsWritten     float64 `json:"rows_written,omitempty" yaml:"rows_written,omitempty"`
	ServedByColo    string  `json:"served_by_colo,omitempty" yaml:"served_by_colo,omitempty"`
	ServedByPrimary bool    `json:"served_by_primary,omitempty" yaml:"served_by_primary,omitempty"`
	SizeAfter       float64 `json:"size_after,omitempty" yaml:"size_after,omitempty"`
}

// D1RawStatementResult is one statement result of a D1 raw query (rows are
// positional arrays).
type D1RawStatementResult struct {
	Success bool    `json:"success" yaml:"success"`
	Results [][]any `json:"results,omitempty" yaml:"results,omitempty"`
	Meta    *D1Meta `json:"meta,omitempty" yaml:"meta,omitempty"`
}

// D1ExportResult is the D1 export job response.
type D1ExportResult struct {
	Status     string   `json:"status,omitempty" yaml:"status,omitempty"`
	AtBookmark string   `json:"at_bookmark,omitempty" yaml:"at_bookmark,omitempty"`
	Filename   string   `json:"filename,omitempty" yaml:"filename,omitempty"`
	SignedURL  string   `json:"signed_url,omitempty" yaml:"signed_url,omitempty"`
	Messages   []string `json:"messages,omitempty" yaml:"messages,omitempty"`
	Error      string   `json:"error,omitempty" yaml:"error,omitempty"`
}

// D1ImportResult is the D1 import step response.
type D1ImportResult struct {
	Status        string   `json:"status,omitempty" yaml:"status,omitempty"`
	Filename      string   `json:"filename,omitempty" yaml:"filename,omitempty"`
	UploadURL     string   `json:"upload_url,omitempty" yaml:"upload_url,omitempty"`
	FinalBookmark string   `json:"final_bookmark,omitempty" yaml:"final_bookmark,omitempty"`
	NumQueries    float64  `json:"num_queries,omitempty" yaml:"num_queries,omitempty"`
	Messages      []string `json:"messages,omitempty" yaml:"messages,omitempty"`
	Error         string   `json:"error,omitempty" yaml:"error,omitempty"`
}

// D1Bookmark is the time-travel bookmark response.
type D1Bookmark struct {
	Bookmark string `json:"bookmark" yaml:"bookmark"`
}

// D1RestoreResult is the time-travel restore response.
type D1RestoreResult struct {
	Bookmark         string `json:"bookmark,omitempty" yaml:"bookmark,omitempty"`
	PreviousBookmark string `json:"previous_bookmark,omitempty" yaml:"previous_bookmark,omitempty"`
	Message          string `json:"message,omitempty" yaml:"message,omitempty"`
}

// Queue is the normalized Queues queue model.
type Queue struct {
	QueueID             string          `json:"queue_id" yaml:"queue_id"`
	QueueName           string          `json:"queue_name" yaml:"queue_name"`
	CreatedOn           string          `json:"created_on,omitempty" yaml:"created_on,omitempty"`
	ModifiedOn          string          `json:"modified_on,omitempty" yaml:"modified_on,omitempty"`
	ConsumersTotalCount float64         `json:"consumers_total_count,omitempty" yaml:"consumers_total_count,omitempty"`
	ProducersTotalCount float64         `json:"producers_total_count,omitempty" yaml:"producers_total_count,omitempty"`
	Settings            *QueueSettings  `json:"settings,omitempty" yaml:"settings,omitempty"`
	Consumers           []QueueConsumer `json:"consumers,omitempty" yaml:"consumers,omitempty"`
}

// QueueSettings are the queue delivery settings.
type QueueSettings struct {
	DeliveryDelay          float64 `json:"delivery_delay,omitempty" yaml:"delivery_delay,omitempty"`
	DeliveryPaused         bool    `json:"delivery_paused,omitempty" yaml:"delivery_paused,omitempty"`
	MessageRetentionPeriod float64 `json:"message_retention_period,omitempty" yaml:"message_retention_period,omitempty"`
}

// QueueConsumer is the normalized consumer model.
type QueueConsumer struct {
	ConsumerID      string          `json:"consumer_id" yaml:"consumer_id"`
	Type            string          `json:"type,omitempty" yaml:"type,omitempty"`
	ScriptName      string          `json:"script_name,omitempty" yaml:"script_name,omitempty"`
	DeadLetterQueue string          `json:"dead_letter_queue,omitempty" yaml:"dead_letter_queue,omitempty"`
	QueueName       string          `json:"queue_name,omitempty" yaml:"queue_name,omitempty"`
	Settings        json.RawMessage `json:"settings,omitempty" yaml:"settings,omitempty"`
	CreatedOn       string          `json:"created_on,omitempty" yaml:"created_on,omitempty"`
}

// QueueMetrics is the queue backlog metrics model.
type QueueMetrics struct {
	BacklogBytes             float64 `json:"backlog_bytes" yaml:"backlog_bytes"`
	BacklogCount             float64 `json:"backlog_count" yaml:"backlog_count"`
	OldestMessageTimestampMs float64 `json:"oldest_message_timestamp_ms" yaml:"oldest_message_timestamp_ms"`
}

// QueueMessage is one pulled or peeked message.
type QueueMessage struct {
	ID          string          `json:"id" yaml:"id"`
	Attempts    float64         `json:"attempts,omitempty" yaml:"attempts,omitempty"`
	Body        string          `json:"body" yaml:"body"`
	LeaseID     string          `json:"lease_id,omitempty" yaml:"lease_id,omitempty"`
	Metadata    json.RawMessage `json:"metadata,omitempty" yaml:"metadata,omitempty"`
	TimestampMs float64         `json:"timestamp_ms,omitempty" yaml:"timestamp_ms,omitempty"`
}

// QueuePullResult is the result of a message pull or peek.
type QueuePullResult struct {
	Messages            []QueueMessage `json:"messages" yaml:"messages"`
	MessageBacklogCount float64        `json:"message_backlog_count,omitempty" yaml:"message_backlog_count,omitempty"`
}

// QueueAckResult is the result of a message ack.
type QueueAckResult struct {
	AckCount   float64           `json:"ackCount" yaml:"ackCount"`
	RetryCount float64           `json:"retryCount" yaml:"retryCount"`
	Warnings   map[string]string `json:"warnings,omitempty" yaml:"warnings,omitempty"`
}

// QueuePurgeStatus is the queue purge job status.
type QueuePurgeStatus struct {
	Completed string `json:"completed" yaml:"completed"`
	StartedAt string `json:"started_at" yaml:"started_at"`
}
