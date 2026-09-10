package cloudflare

import (
	"context"
	"encoding/json"
	"net/url"

	"github.com/hnkNkm/flareadm/internal/errors"
	"github.com/hnkNkm/flareadm/internal/pagination"
)

// QueueConsumerTypes are the accepted consumer types.
var QueueConsumerTypes = []string{"worker", "http_pull"}

// QueueContentTypes are the accepted message content types.
var QueueContentTypes = []string{"text", "json"}

func queuesPath(accountID string) string {
	return "/accounts/" + url.PathEscape(accountID) + "/queues"
}

func queuePath(accountID, queueID, suffix string) string {
	p := queuesPath(accountID) + "/" + url.PathEscape(queueID)
	if suffix != "" {
		p += "/" + suffix
	}
	return p
}

// cfQueue mirrors the queue JSON shape.
type cfQueue struct {
	QueueID             string          `json:"queue_id"`
	QueueName           string          `json:"queue_name"`
	CreatedOn           string          `json:"created_on"`
	ModifiedOn          string          `json:"modified_on"`
	ConsumersTotalCount float64         `json:"consumers_total_count"`
	ProducersTotalCount float64         `json:"producers_total_count"`
	Settings            *QueueSettings  `json:"settings"`
	Consumers           []QueueConsumer `json:"consumers"`
}

func convertQueue(cf cfQueue) Queue {
	return Queue(cf)
}

// ListQueues lists queues of an account. The API is not paginated in the
// SDK's request surface; --max-items truncates client-side.
func (c *Client) ListQueues(ctx context.Context, accountID string, pol pagination.Policy) (*ListResult[Queue], error) {
	if err := pol.Validate(); err != nil {
		return nil, errors.Usage("%s", err.Error())
	}
	env, raw, err := c.requestJSON(ctx, "GET", queuesPath(accountID), nil, nil, "")
	if err != nil {
		return nil, err
	}
	if c.raw {
		return &ListResult[Queue]{RawBody: raw}, nil
	}
	var items []Queue
	if err := decodeResult(env, &items); err != nil {
		return nil, errors.Wrap(errors.CodeUnclassified, "decoding queue list", err)
	}
	items = truncateQueues(items, pol.MaxItems)
	return &ListResult[Queue]{Items: items}, nil
}

func truncateQueues(items []Queue, max int) []Queue {
	if max > 0 && len(items) > max {
		return items[:max]
	}
	return items
}

// GetQueue fetches one queue.
func (c *Client) GetQueue(ctx context.Context, accountID, queueID string) (*GetResult[Queue], error) {
	env, raw, err := c.requestJSON(ctx, "GET", queuePath(accountID, queueID, ""), nil, nil, "")
	if err != nil {
		return nil, err
	}
	var cf cfQueue
	if err := decodeResult(env, &cf); err != nil {
		return nil, errors.Wrap(errors.CodeUnclassified, "decoding queue response", err)
	}
	return &GetResult[Queue]{Item: convertQueue(cf), RawBody: raw}, nil
}

// CreateQueue creates a queue (POST; never automatically retried).
func (c *Client) CreateQueue(ctx context.Context, accountID, queueName string) (*GetResult[Queue], error) {
	if queueName == "" {
		return nil, errors.Usage("--name is required")
	}
	raw, err := json.Marshal(map[string]any{"queue_name": queueName})
	if err != nil {
		return nil, err
	}
	env, respRaw, err := c.requestJSON(ctx, "POST", queuesPath(accountID), nil, raw, "application/json")
	if err != nil {
		return nil, err
	}
	var cf cfQueue
	if err := decodeResult(env, &cf); err != nil {
		return nil, errors.Wrap(errors.CodeUnclassified, "decoding queue response", err)
	}
	return &GetResult[Queue]{Item: convertQueue(cf), RawBody: respRaw}, nil
}

// QueueUpdate carries the queue settings overrides (PATCH semantics).
type QueueUpdate struct {
	DeliveryDelay          *float64
	DeliveryPaused         *bool
	MessageRetentionPeriod *float64
}

// UpdateQueue patches the queue settings (idempotent).
func (c *Client) UpdateQueue(ctx context.Context, accountID, queueID string, up QueueUpdate) (*GetResult[Queue], error) {
	if up.DeliveryDelay == nil && up.DeliveryPaused == nil && up.MessageRetentionPeriod == nil {
		return nil, errors.Usage("nothing to update; pass at least one of --delivery-delay, --delivery-paused, --message-retention-period")
	}
	settings := map[string]any{}
	if up.DeliveryDelay != nil {
		settings["delivery_delay"] = *up.DeliveryDelay
	}
	if up.DeliveryPaused != nil {
		settings["delivery_paused"] = *up.DeliveryPaused
	}
	if up.MessageRetentionPeriod != nil {
		settings["message_retention_period"] = *up.MessageRetentionPeriod
	}
	raw, err := json.Marshal(map[string]any{"queue": map[string]any{"settings": settings}})
	if err != nil {
		return nil, err
	}
	env, respRaw, err := c.requestJSON(ctx, "PATCH", queuePath(accountID, queueID, ""), nil, raw, "application/json")
	if err != nil {
		return nil, err
	}
	var cf cfQueue
	if err := decodeResult(env, &cf); err != nil {
		return nil, errors.Wrap(errors.CodeUnclassified, "decoding queue response", err)
	}
	return &GetResult[Queue]{Item: convertQueue(cf), RawBody: respRaw}, nil
}

// DeleteQueue deletes a queue (DELETE, idempotent).
func (c *Client) DeleteQueue(ctx context.Context, accountID, queueID string) error {
	_, _, err := c.requestJSON(ctx, "DELETE", queuePath(accountID, queueID, ""), nil, nil, "")
	return err
}

// QueueMetricsGet reads the queue backlog metrics.
func (c *Client) QueueMetricsGet(ctx context.Context, accountID, queueID string) (*GetResult[QueueMetrics], error) {
	env, raw, err := c.requestJSON(ctx, "GET", queuePath(accountID, queueID, "metrics"), nil, nil, "")
	if err != nil {
		return nil, err
	}
	var item QueueMetrics
	if err := decodeResult(env, &item); err != nil {
		return nil, errors.Wrap(errors.CodeUnclassified, "decoding queue metrics response", err)
	}
	return &GetResult[QueueMetrics]{Item: item, RawBody: raw}, nil
}

// ---- consumers ------------------------------------------------------------

// ListConsumers lists the consumers of a queue (not paginated in the SDK's
// request surface).
func (c *Client) ListConsumers(ctx context.Context, accountID, queueID string, pol pagination.Policy) (*ListResult[QueueConsumer], error) {
	if err := pol.Validate(); err != nil {
		return nil, errors.Usage("%s", err.Error())
	}
	env, raw, err := c.requestJSON(ctx, "GET", queuePath(accountID, queueID, "consumers"), nil, nil, "")
	if err != nil {
		return nil, err
	}
	if c.raw {
		return &ListResult[QueueConsumer]{RawBody: raw}, nil
	}
	var items []QueueConsumer
	if err := decodeResult(env, &items); err != nil {
		return nil, errors.Wrap(errors.CodeUnclassified, "decoding consumer list", err)
	}
	if pol.MaxItems > 0 && len(items) > pol.MaxItems {
		items = items[:pol.MaxItems]
	}
	return &ListResult[QueueConsumer]{Items: items}, nil
}

// GetConsumer fetches one consumer.
func (c *Client) GetConsumer(ctx context.Context, accountID, queueID, consumerID string) (*GetResult[QueueConsumer], error) {
	env, raw, err := c.requestJSON(ctx, "GET", queuePath(accountID, queueID, "consumers/"+url.PathEscape(consumerID)), nil, nil, "")
	if err != nil {
		return nil, err
	}
	var item QueueConsumer
	if err := decodeResult(env, &item); err != nil {
		return nil, errors.Wrap(errors.CodeUnclassified, "decoding consumer response", err)
	}
	return &GetResult[QueueConsumer]{Item: item, RawBody: raw}, nil
}

// QueueConsumerParams is the consumer write model.
type QueueConsumerParams struct {
	Type            string
	ScriptName      string
	DeadLetterQueue string
	Settings        json.RawMessage
}

// CreateConsumer creates a consumer (POST; never automatically retried).
func (c *Client) CreateConsumer(ctx context.Context, accountID, queueID string, p QueueConsumerParams) (*GetResult[QueueConsumer], error) {
	if p.Type == "" {
		return nil, errors.Usage("--type is required (worker, http_pull)")
	}
	if p.Type == "worker" && p.ScriptName == "" {
		return nil, errors.Usage("--script is required for worker consumers")
	}
	body := map[string]any{"type": p.Type}
	if p.ScriptName != "" {
		body["script_name"] = p.ScriptName
	}
	if p.DeadLetterQueue != "" {
		body["dead_letter_queue"] = p.DeadLetterQueue
	}
	if len(p.Settings) > 0 {
		body["settings"] = p.Settings
	}
	raw, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	env, respRaw, err := c.requestJSON(ctx, "POST", queuePath(accountID, queueID, "consumers"), nil, raw, "application/json")
	if err != nil {
		return nil, err
	}
	var item QueueConsumer
	if err := decodeResult(env, &item); err != nil {
		return nil, errors.Wrap(errors.CodeUnclassified, "decoding consumer response", err)
	}
	return &GetResult[QueueConsumer]{Item: item, RawBody: respRaw}, nil
}

// UpdateConsumer patches a consumer with the provided fields (idempotent).
func (c *Client) UpdateConsumer(ctx context.Context, accountID, queueID, consumerID string, p QueueConsumerParams) (*GetResult[QueueConsumer], error) {
	body := map[string]any{}
	if p.Type != "" {
		body["type"] = p.Type
	}
	if p.ScriptName != "" {
		body["script_name"] = p.ScriptName
	}
	if p.DeadLetterQueue != "" {
		body["dead_letter_queue"] = p.DeadLetterQueue
	}
	if len(p.Settings) > 0 {
		body["settings"] = p.Settings
	}
	if len(body) == 0 {
		return nil, errors.Usage("nothing to update; pass at least one of --type, --script, --dead-letter-queue, --settings")
	}
	raw, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	env, respRaw, err := c.requestJSON(ctx, "PATCH", queuePath(accountID, queueID, "consumers/"+url.PathEscape(consumerID)), nil, raw, "application/json")
	if err != nil {
		return nil, err
	}
	var item QueueConsumer
	if err := decodeResult(env, &item); err != nil {
		return nil, errors.Wrap(errors.CodeUnclassified, "decoding consumer response", err)
	}
	return &GetResult[QueueConsumer]{Item: item, RawBody: respRaw}, nil
}

// DeleteConsumer deletes a consumer (DELETE, idempotent).
func (c *Client) DeleteConsumer(ctx context.Context, accountID, queueID, consumerID string) error {
	_, _, err := c.requestJSON(ctx, "DELETE", queuePath(accountID, queueID, "consumers/"+url.PathEscape(consumerID)), nil, nil, "")
	return err
}

// ---- messages -------------------------------------------------------------

// QueuePushParams is the message push model. Body is sent verbatim as the
// JSON value for content type "json" and as a string for "text".
type QueuePushParams struct {
	Body         json.RawMessage
	ContentType  string
	DelaySeconds float64
}

// PushMessage publishes one message (POST; never automatically retried).
func (c *Client) PushMessage(ctx context.Context, accountID, queueID string, p QueuePushParams) (*GetResult[json.RawMessage], error) {
	if len(p.Body) == 0 {
		return nil, errors.Usage("--body is required")
	}
	if !containsString(QueueContentTypes, p.ContentType) {
		return nil, errors.Usage("invalid --content-type %q (supported: text, json)", p.ContentType)
	}
	body := map[string]any{"body": p.Body, "content_type": p.ContentType}
	if p.DelaySeconds > 0 {
		body["delay_seconds"] = p.DelaySeconds
	}
	raw, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	env, respRaw, err := c.requestJSON(ctx, "POST", queuePath(accountID, queueID, "messages"), nil, raw, "application/json")
	if err != nil {
		return nil, err
	}
	return &GetResult[json.RawMessage]{Item: env.Result, RawBody: respRaw}, nil
}

// BulkPushMessages publishes a batch (POST /messages/batch).
func (c *Client) BulkPushMessages(ctx context.Context, accountID, queueID string, messages []json.RawMessage, delaySeconds float64) (*GetResult[json.RawMessage], error) {
	if len(messages) == 0 {
		return nil, errors.Usage("--messages is required (JSON array of message objects)")
	}
	body := map[string]any{"messages": messages}
	if delaySeconds > 0 {
		body["delay_seconds"] = delaySeconds
	}
	raw, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	env, respRaw, err := c.requestJSON(ctx, "POST", queuePath(accountID, queueID, "messages/batch"), nil, raw, "application/json")
	if err != nil {
		return nil, err
	}
	return &GetResult[json.RawMessage]{Item: env.Result, RawBody: respRaw}, nil
}

// PullMessages pulls messages (POST /messages/pull).
func (c *Client) PullMessages(ctx context.Context, accountID, queueID string, batchSize int, visibilityTimeoutMs int64) (*GetResult[QueuePullResult], error) {
	body := map[string]any{}
	if batchSize > 0 {
		body["batch_size"] = batchSize
	}
	if visibilityTimeoutMs > 0 {
		body["visibility_timeout_ms"] = visibilityTimeoutMs
	}
	raw, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	env, respRaw, err := c.requestJSON(ctx, "POST", queuePath(accountID, queueID, "messages/pull"), nil, raw, "application/json")
	if err != nil {
		return nil, err
	}
	var item QueuePullResult
	if err := decodeResult(env, &item); err != nil {
		return nil, errors.Wrap(errors.CodeUnclassified, "decoding pull response", err)
	}
	return &GetResult[QueuePullResult]{Item: item, RawBody: respRaw}, nil
}

// PeekMessages peeks messages (POST /messages/peek).
func (c *Client) PeekMessages(ctx context.Context, accountID, queueID string, batchSize int) (*GetResult[QueuePullResult], error) {
	body := map[string]any{}
	if batchSize > 0 {
		body["batch_size"] = batchSize
	}
	raw, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	env, respRaw, err := c.requestJSON(ctx, "POST", queuePath(accountID, queueID, "messages/peek"), nil, raw, "application/json")
	if err != nil {
		return nil, err
	}
	var item QueuePullResult
	if err := decodeResult(env, &item); err != nil {
		return nil, errors.Wrap(errors.CodeUnclassified, "decoding peek response", err)
	}
	return &GetResult[QueuePullResult]{Item: item, RawBody: respRaw}, nil
}

// AckMessages acknowledges or retries messages (POST /messages/ack).
func (c *Client) AckMessages(ctx context.Context, accountID, queueID string, acks, retries []string) (*GetResult[QueueAckResult], error) {
	if len(acks) == 0 && len(retries) == 0 {
		return nil, errors.Usage("pass at least one --ack LEASE_ID or --retry LEASE_ID")
	}
	body := map[string]any{}
	if len(acks) > 0 {
		body["acks"] = acks
	}
	if len(retries) > 0 {
		body["retries"] = retries
	}
	raw, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	env, respRaw, err := c.requestJSON(ctx, "POST", queuePath(accountID, queueID, "messages/ack"), nil, raw, "application/json")
	if err != nil {
		return nil, err
	}
	var item QueueAckResult
	if err := decodeResult(env, &item); err != nil {
		return nil, errors.Wrap(errors.CodeUnclassified, "decoding ack response", err)
	}
	return &GetResult[QueueAckResult]{Item: item, RawBody: respRaw}, nil
}

// PurgeMessages removes specific messages by ref/lease id
// (POST /messages/purge).
func (c *Client) PurgeMessages(ctx context.Context, accountID, queueID string, refs []string) error {
	if len(refs) == 0 {
		return errors.Usage("pass at least one --ref LEASE_ID")
	}
	raw, err := json.Marshal(map[string]any{"refs": refs})
	if err != nil {
		return err
	}
	_, _, err = c.requestJSON(ctx, "POST", queuePath(accountID, queueID, "messages/purge"), nil, raw, "application/json")
	return err
}

// StartQueuePurge starts a queue purge job (POST /purge).
func (c *Client) StartQueuePurge(ctx context.Context, accountID, queueID string, permanent bool) (*GetResult[Queue], error) {
	body := map[string]any{}
	if permanent {
		body["delete_messages_permanently"] = true
	}
	raw, err := json.Marshal(body)
	if err != nil {
		return nil, err
	}
	env, respRaw, err := c.requestJSON(ctx, "POST", queuePath(accountID, queueID, "purge"), nil, raw, "application/json")
	if err != nil {
		return nil, err
	}
	var cf cfQueue
	if err := decodeResult(env, &cf); err != nil {
		return nil, errors.Wrap(errors.CodeUnclassified, "decoding purge response", err)
	}
	return &GetResult[Queue]{Item: convertQueue(cf), RawBody: respRaw}, nil
}

// QueuePurgeStatusGet reads the queue purge job status (GET /purge).
func (c *Client) QueuePurgeStatusGet(ctx context.Context, accountID, queueID string) (*GetResult[QueuePurgeStatus], error) {
	env, raw, err := c.requestJSON(ctx, "GET", queuePath(accountID, queueID, "purge"), nil, nil, "")
	if err != nil {
		return nil, err
	}
	var item QueuePurgeStatus
	if err := decodeResult(env, &item); err != nil {
		return nil, errors.Wrap(errors.CodeUnclassified, "decoding purge status response", err)
	}
	return &GetResult[QueuePurgeStatus]{Item: item, RawBody: raw}, nil
}
