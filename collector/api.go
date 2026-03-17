package collector

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"time"
)

const (
	maxRetries      = 3
	baseRetryDelay  = 100 * time.Millisecond
	maxResponseSize = 10 * 1024 * 1024
)

func (c *ProxmoxCollector) authenticate() error {
	c.mutex.Lock()
	defer c.mutex.Unlock()

	if c.config.TokenID != "" && c.config.TokenSecret != "" {
		return nil
	}

	if c.ticket != "" && time.Since(c.ticketTime) < time.Hour {
		return nil
	}

	apiURL := fmt.Sprintf("https://%s:%d/api2/json/access/ticket", c.config.Host, c.config.Port)

	data := url.Values{}
	data.Set("username", c.config.User)
	data.Set("password", c.config.Password)

	resp, err := c.client.PostForm(apiURL, data)
	if err != nil {
		return fmt.Errorf("authentication failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("authentication failed with status: %d", resp.StatusCode)
	}

	var result authTicketResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return fmt.Errorf("failed to decode auth response: %w", err)
	}

	c.ticket = result.Data.Ticket
	c.csrf = result.Data.CSRF
	c.ticketTime = time.Now()

	return nil
}

func (c *ProxmoxCollector) apiRequest(path string) ([]byte, error) {
	apiURL := fmt.Sprintf("https://%s:%d/api2/json%s", c.config.Host, c.config.Port, path)

	var lastErr error
	for attempt := range maxRetries {
		ctx, cancel := context.WithTimeout(context.Background(), c.config.Timeout)
		if err := c.limiter.Wait(ctx); err != nil {
			cancel()
			return nil, fmt.Errorf("rate limiter: %w", err)
		}

		req, err := http.NewRequestWithContext(ctx, "GET", apiURL, nil)
		if err != nil {
			cancel()
			return nil, err
		}

		c.mutex.RLock()
		if c.config.TokenID != "" && c.config.TokenSecret != "" {
			req.Header.Set("Authorization", fmt.Sprintf("PVEAPIToken=%s=%s", c.config.TokenID, c.config.TokenSecret))
		} else {
			req.Header.Set("Cookie", fmt.Sprintf("PVEAuthCookie=%s", c.ticket))
			req.Header.Set("CSRFPreventionToken", c.csrf)
		}
		c.mutex.RUnlock()

		resp, err := c.client.Do(req)
		if err != nil {
			cancel()
			lastErr = err
			if attempt < maxRetries-1 {
				delay := baseRetryDelay * time.Duration(math.Pow(2, float64(attempt)))
				time.Sleep(delay)
			}
			continue
		}

		body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseSize))
		_ = resp.Body.Close()
		cancel()

		if resp.StatusCode == http.StatusUnauthorized && attempt < maxRetries-1 {
			if authErr := c.authenticate(); authErr != nil {
				return nil, fmt.Errorf("re-authentication failed: %w", authErr)
			}
			continue
		}

		if resp.StatusCode != http.StatusOK {
			lastErr = fmt.Errorf("API request failed with status: %d", resp.StatusCode)
			if attempt < maxRetries-1 && resp.StatusCode >= 500 {
				delay := baseRetryDelay * time.Duration(math.Pow(2, float64(attempt)))
				time.Sleep(delay)
				continue
			}
			return nil, lastErr
		}

		if err != nil {
			return nil, fmt.Errorf("failed to read response body: %w", err)
		}

		return body, nil
	}

	return nil, fmt.Errorf("max retries exceeded: %w", lastErr)
}

func unmarshalJSON(data []byte, v any) error {
	return json.Unmarshal(data, v)
}

func fetchJSON[T any](c *ProxmoxCollector, path string) (T, error) {
	var zero T
	data, err := c.apiRequest(path)
	if err != nil {
		return zero, err
	}
	var result T
	if err := json.Unmarshal(data, &result); err != nil {
		return zero, fmt.Errorf("unmarshal %s: %w", path, err)
	}
	return result, nil
}
