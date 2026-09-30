package collector

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	maxRetries      = 3
	baseRetryDelay  = 100 * time.Millisecond
	maxResponseSize = 10 * 1024 * 1024
)

type authTicketGeneration struct {
	refresh *ticketRefresh
}

type ticketRefresh struct {
	done  chan struct{}
	err   error
	joins int
}

type requestCredentials struct {
	ticket     string
	csrf       string
	ticketTime time.Time
	generation *authTicketGeneration
	token      bool
}

func (c *ProxmoxCollector) authenticate() error {
	return c.authenticateTicket(false, "", time.Time{}, nil)
}

func (c *ProxmoxCollector) authenticateAfterUnauthorized(credentials requestCredentials) error {
	return c.authenticateTicket(true, credentials.ticket, credentials.ticketTime, credentials.generation)
}

func (c *ProxmoxCollector) authenticateTicket(force bool, rejectedTicket string, rejectedTicketTime time.Time, generation *authTicketGeneration) error {
	c.mutex.Lock()
	if c.config.TokenID != "" && c.config.TokenSecret != "" {
		c.mutex.Unlock()
		return nil
	}

	currentGeneration := c.currentTicketGenerationLocked()
	if force {
		if generation.refresh != nil {
			refresh := generation.refresh
			refresh.joins++
			c.mutex.Unlock()
			return waitForTicketRefresh(refresh)
		}
		if generation != currentGeneration || c.ticket != rejectedTicket || c.ticketTime.After(rejectedTicketTime) {
			c.mutex.Unlock()
			return nil
		}
	} else if currentGeneration.refresh != nil {
		refresh := currentGeneration.refresh
		refresh.joins++
		c.mutex.Unlock()
		return waitForTicketRefresh(refresh)
	}
	if !force && c.ticket != "" && time.Since(c.ticketTime) < time.Hour {
		c.mutex.Unlock()
		return nil
	}

	refresh := &ticketRefresh{done: make(chan struct{})}
	currentGeneration.refresh = refresh
	c.mutex.Unlock()

	ticket, csrf, err := c.login()

	c.mutex.Lock()
	refresh.err = err
	if err == nil {
		c.ticket = ticket
		c.csrf = csrf
		c.ticketTime = time.Now()
	}
	if c.ticketGeneration == currentGeneration {
		c.ticketGeneration = &authTicketGeneration{}
	}
	close(refresh.done)
	c.mutex.Unlock()
	return err
}

func (c *ProxmoxCollector) currentTicketGenerationLocked() *authTicketGeneration {
	if c.ticketGeneration == nil {
		c.ticketGeneration = &authTicketGeneration{}
	}
	return c.ticketGeneration
}

func waitForTicketRefresh(refresh *ticketRefresh) error {
	<-refresh.done
	return refresh.err
}

func (c *ProxmoxCollector) credentialsForRequest() (requestCredentials, error) {
	for {
		c.mutex.Lock()
		if c.config.TokenID != "" && c.config.TokenSecret != "" {
			c.mutex.Unlock()
			return requestCredentials{token: true}, nil
		}

		generation := c.currentTicketGenerationLocked()
		if generation.refresh == nil {
			credentials := requestCredentials{
				ticket:     c.ticket,
				csrf:       c.csrf,
				ticketTime: c.ticketTime,
				generation: generation,
			}
			c.mutex.Unlock()
			return credentials, nil
		}

		refresh := generation.refresh
		refresh.joins++
		c.mutex.Unlock()
		if err := waitForTicketRefresh(refresh); err != nil {
			return requestCredentials{}, err
		}
	}
}

func (c *ProxmoxCollector) login() (string, string, error) {
	apiURL, err := buildAPIURL(c.config.Host, c.config.Port, "/access/ticket")
	if err != nil {
		return "", "", fmt.Errorf("authentication failed: %w", err)
	}

	data := url.Values{}
	data.Set("username", c.config.User)
	data.Set("password", c.config.Password)

	resp, err := c.client.PostForm(apiURL, data)
	if err != nil {
		return "", "", fmt.Errorf("authentication failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return "", "", fmt.Errorf("authentication failed with status: %d", resp.StatusCode)
	}

	body, err := readBoundedBody(resp.Body)
	if err != nil {
		return "", "", fmt.Errorf("failed to read auth response: %w", err)
	}

	var result authTicketResponse
	if err := json.Unmarshal(body, &result); err != nil {
		return "", "", fmt.Errorf("failed to decode auth response: %w", err)
	}

	return result.Data.Ticket, result.Data.CSRF, nil
}

func (c *ProxmoxCollector) apiRequest(path string) ([]byte, error) {
	apiURL, err := buildAPIURL(c.config.Host, c.config.Port, path)
	if err != nil {
		return nil, err
	}

	var lastErr error
	for attempt := range maxRetries {
		credentials, err := c.credentialsForRequest()
		if err != nil {
			return nil, fmt.Errorf("re-authentication failed: %w", err)
		}

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

		if credentials.token {
			req.Header.Set("Authorization", fmt.Sprintf("PVEAPIToken=%s=%s", c.config.TokenID, c.config.TokenSecret))
		} else {
			req.Header.Set("Cookie", fmt.Sprintf("PVEAuthCookie=%s", credentials.ticket))
			req.Header.Set("CSRFPreventionToken", credentials.csrf)
		}

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

		body, err := readBoundedBody(resp.Body)
		_ = resp.Body.Close()
		cancel()
		if resp.StatusCode == http.StatusUnauthorized && attempt < maxRetries-1 {
			if authErr := c.authenticateAfterUnauthorized(credentials); authErr != nil {
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

func readBoundedBody(body io.Reader) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(body, maxResponseSize+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxResponseSize {
		return nil, fmt.Errorf("response body exceeds %d bytes", maxResponseSize)
	}
	return data, nil
}

func buildAPIURL(host string, port int, endpoint string) (string, error) {
	normalizedHost, err := normalizeAPIHost(host)
	if err != nil {
		return "", err
	}
	if port < 1 || port > 65535 {
		return "", fmt.Errorf("invalid API port %d", port)
	}

	relative, err := url.ParseRequestURI(endpoint)
	if err != nil || !strings.HasPrefix(endpoint, "/") || relative.IsAbs() || relative.Host != "" {
		return "", fmt.Errorf("invalid API path %q", endpoint)
	}

	base := &url.URL{
		Scheme: "https",
		Host:   net.JoinHostPort(normalizedHost, strconv.Itoa(port)),
		Path:   "/api2/json" + relative.Path,
	}
	base.RawPath = "/api2/json" + relative.EscapedPath()
	base.RawQuery = relative.RawQuery
	return base.String(), nil
}

func normalizeAPIHost(host string) (string, error) {
	if host == "" || strings.TrimSpace(host) != host || strings.ContainsAny(host, "/\\?#@%") {
		return "", fmt.Errorf("invalid API host %q", host)
	}

	if strings.HasPrefix(host, "[") || strings.HasSuffix(host, "]") {
		if !strings.HasPrefix(host, "[") || !strings.HasSuffix(host, "]") {
			return "", fmt.Errorf("invalid API host %q", host)
		}
		host = strings.TrimSuffix(strings.TrimPrefix(host, "["), "]")
		ip := net.ParseIP(host)
		if ip == nil || ip.To4() != nil {
			return "", fmt.Errorf("invalid API host %q", host)
		}
		return host, nil
	}

	if strings.Contains(host, ":") {
		if ip := net.ParseIP(host); ip != nil && ip.To4() == nil {
			return host, nil
		}
		return "", fmt.Errorf("invalid API host %q", host)
	}
	if strings.ContainsAny(host, "[]") {
		return "", fmt.Errorf("invalid API host %q", host)
	}
	return host, nil
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
