# Development Guide

## Prerequisites

- Go 1.21 or later
- Access to a Proxmox VE instance for testing

## Local Development Setup

### 1. Clone the Repository

```bash
git clone https://github.com/bigtcze/pve-exporter.git
cd pve-exporter
```

### 2. Install Dependencies

```bash
go mod download
```

### 3. Create Configuration

Copy the example configuration:

```bash
cp config.example.yml config.yml
```

Edit `config.yml` with your Proxmox credentials.

### 4. Run Locally

```bash
go run . -config config.yml
```

The exporter will be available at `http://localhost:9221/metrics`

## Project Structure

```
pve-exporter/
├── main.go                 # Application entry point
├── config/
│   └── config.go          # Configuration management
├── collector/
│   ├── proxmox.go         # Proxmox metrics collector
│   └── zfs.go             # ZFS metrics collector
├── examples/
│   └── prometheus.yml     # Example Prometheus config
├── .github/
│   └── workflows/         # CI/CD workflows
├── .agent/
│   └── memory/            # AI persistent memory
└── README.md              # Documentation
```

## Testing

### Run Unit Tests

```bash
go test -v ./...
```

### Run Tests with Coverage

```bash
go test -v -race -coverprofile=coverage.out ./...
go tool cover -html=coverage.out
```

### Run Linting

```bash
go vet ./...
gofmt -s -l .
```

## Building

### Build Binary

```bash
go build -o pve-exporter .
```

### Build with Version Info

```bash
VERSION=v1.0.0
COMMIT=$(git rev-parse --short HEAD)
DATE=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

go build -ldflags "-X main.version=${VERSION} -X main.commit=${COMMIT} -X main.date=${DATE}" -o pve-exporter .
```

### Cross-compile for Linux

```bash
GOOS=linux GOARCH=amd64 go build -o pve-exporter-linux-amd64 .
```

## Adding New Metrics

### 1. Define Metric Descriptor

In the appropriate collector file, add a new `prometheus.Desc`:

```go
myMetric: prometheus.NewDesc(
    "pve_my_metric",
    "Description of my metric",
    []string{"label1", "label2"}, nil,
)
```

### 2. Register in Describe Method

```go
func (c *ProxmoxCollector) Describe(ch chan<- *prometheus.Desc) {
    // ... existing metrics
    ch <- c.myMetric
}
```

### 3. Collect Metric Data

```go
func (c *ProxmoxCollector) Collect(ch chan<- prometheus.Metric) {
    // ... collect data
    ch <- prometheus.MustNewConstMetric(
        c.myMetric,
        prometheus.GaugeValue,
        value,
        "label1_value", "label2_value",
    )
}
```

### 4. Document the Metric

Add documentation to `.agent/memory/metrics_reference.md`

## Debugging

### Enable Verbose Logging

The exporter logs to stdout. Run with:

```bash
./pve-exporter -config config.yml 2>&1 | tee exporter.log
```

### Test Proxmox API Connectivity

```bash
curl -k -d "username=root@pam&password=yourpassword" \
  https://proxmox.example.com:8006/api2/json/access/ticket
```

### Check ZFS Stats Availability

```bash
cat /proc/spl/kstat/zfs/arcstats
```

## Contributing

### Code Style

- Follow standard Go formatting (`gofmt`)
- Use meaningful variable names
- Add comments for exported functions
- Keep functions focused and small

### Commit Messages

Use conventional commit format:

```
feat: add new metric for pool fragmentation
fix: correct memory calculation in ZFS collector
docs: update README with new configuration options
chore: update dependencies
```

### Pull Request Process

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Ensure all tests pass
6. Submit a pull request

### Pre-Push Verification

Before pushing, verify the build:
```bash
go build -o pve-exporter .
```

## Release Process

Releases are automated via GitHub Actions. The release body comes from the annotated tag message.

1. Commit and push changes to `main` branch
2. Create an **annotated tag** with release summary:
   ```bash
   git tag -a v1.0.9 -m "v1.0.9

   ## 🚀 What's New
   - Feature X
   - Feature Y

   ## 🐛 Bug Fixes
   - Fixed issue Z
   "
   git push origin v1.0.9
   ```
3. GitHub Actions will:
   - Run tests
   - Build multi-arch binaries (amd64, arm64, armv7)
   - Create GitHub release with tag annotation as body

## Troubleshooting

### "Authentication failed"
- Check Proxmox credentials
- Verify API token has correct permissions
- Ensure Proxmox API is accessible

### "No ZFS metrics"
- Check if ZFS is installed
- Verify `/proc/spl/kstat/zfs` exists
- Ensure proper permissions to read kstat files

### "Connection refused"
- Check Proxmox host and port
- Verify firewall rules
- Check TLS/SSL settings

## Resources

- [Prometheus Go Client Documentation](https://pkg.go.dev/github.com/prometheus/client_golang)
- [Proxmox VE API Documentation](https://pve.proxmox.com/pve-docs/api-viewer/)
- [ZFS on Linux Documentation](https://openzfs.github.io/openzfs-docs/)
