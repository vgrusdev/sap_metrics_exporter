package soap

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"time"

	"github.com/vgrusdev/sap_metrics_exporter/config"

	"github.com/hooklift/gowsdl/soap"
)

type Client struct {
	config     *config.Config
	httpClient *http.Client
}

func NewClient(cfg *config.Config) *Client {
	return &Client{
		config: cfg,
		httpClient: &http.Client{
			Timeout: cfg.Timeout,
			Transport: &http.Transport{
				MaxIdleConns:        100,
				MaxIdleConnsPerHost: 10,
				IdleConnTimeout:     90 * time.Second,
			},
		},
	}
}

func (c *Client) CreateSOAPClient(endpoint string) *soap.Client {

	config := c.config
	opts := []soap.Option{}

	// Add authentication if configured
	if config.Auth != nil && config.Auth.Username != "" {
		opts = []soap.Option{
			soap.WithBasicAuth(
				config.Auth.Username,
				config.Auth.Password,
			),
		}
	}
	if config.Auth.UseSSL {
		opts = append(opts, soap.WithTLS(&tls.Config{InsecureSkipVerify: config.Auth.TLSSkipVfy}))
	}
	client := soap.NewClient(endpoint, opts...)

	return client
}

func (c *Client) GetSystemInstanceList(ctx context.Context, host, port string) (*SAPInstanceList, error) {
	endpoints := []string{
		fmt.Sprintf("http://%s:%s/sap/bc/soap/rfc", host, port),
		fmt.Sprintf("http://%s:%s/SAPControl.cgi", host, port),
		fmt.Sprintf("http://%s:%s/sap/bc/webdynpro/sap/dba_control", host, port),
	}

	var lastErr error
	for _, endpoint := range endpoints {
		client := c.CreateSOAPClient(endpoint)

		request := &GetSystemInstanceList{}
		response := &SAPInstanceList{}

		if err := client.CallContext(ctx, "GetSystemInstanceList", request, response); err != nil {
			lastErr = err
			continue
		}
		if len(response.Instance) == 0 {
			lastErr = fmt.Errorf("no instances found at %s", endpoint)
			continue
		}
		return response, nil
	}
	return nil, fmt.Errorf("SOAP.Client.GetSystemInstanceList: failed to get instances from any endpoint: %v", lastErr)
}

func (c *Client) GetWPTable(ctx context.Context, host, port string) (*WPTable, error) {
	endpoint := fmt.Sprintf("http://%s:%s/sap/bc/soap/rfc", host, port)
	client := c.CreateSOAPClient(endpoint)

	request := &GetWPTable{}
	response := &WPTable{}

	if err := client.CallContext(ctx, "GetWPTable", request, response); err != nil {
		return nil, fmt.Errorf("GetWPTable failed: %w", err)
	}
	return response, nil
}

func (c *Client) GetQueueStatistic(ctx context.Context, host, port string) (*QueueStatistic, error) {
	endpoint := fmt.Sprintf("http://%s:%s/sap/bc/soap/rfc", host, port)
	client := c.CreateSOAPClient(endpoint)

	request := &GetQueueStatistic{}
	response := &QueueStatistic{}

	if err := client.CallContext(ctx, "GetQueueStatistic", request, response); err != nil {
		return nil, fmt.Errorf("GetQueueStatistic failed: %w", err)
	}
	return response, nil
}

func (c *Client) GetEnqTable(ctx context.Context, host, port string) (*EnqTable, error) {
	endpoint := fmt.Sprintf("http://%s:%s/sap/bc/soap/rfc", host, port)
	client := c.CreateSOAPClient(endpoint)

	request := &GetEnqTable{}
	response := &EnqTable{}

	if err := client.CallContext(ctx, "GetEnqTable", request, response); err != nil {
		return nil, fmt.Errorf("GetEnqTable failed: %w", err)
	}
	return response, nil
}
