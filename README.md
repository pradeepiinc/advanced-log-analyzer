# Advanced Production Log Analyzer

A comprehensive, enterprise-grade log analysis platform with OpenTelemetry-first ingestion, real-time analytics, ML-powered anomaly detection, and extensive integrations.

## 🚀 Features

### Core Capabilities
- **OpenTelemetry-First Ingestion**: Native support for logs, metrics, traces, and events
- **Multi-Protocol Transport**: HTTP/gRPC, Syslog (UDP/TCP), Kafka, Redis Streams
- **Advanced Parsing**: JSON, logfmt, regex/grok patterns, multiline logs
- **PII Detection & Redaction**: Configurable modes (hash, mask, remove)
- **Hot/Warm/Cold Storage**: Elasticsearch, ClickHouse, S3 with intelligent tiering
- **Google-like Search**: DSL, SQL, regex, full-text with faceted navigation
- **Real-time Live Tail**: WebSocket-based streaming with filtering
- **ML Anomaly Detection**: Statistical, clustering, time series, and pattern analysis

### Advanced Features
- **Service Topology Mapping**: Automatic service discovery and dependency tracking
- **Correlation Analysis**: Cross-service troubleshooting and root cause analysis
- **SLO Monitoring**: Error budget burn rate alerts and availability tracking
- **Advanced Alerting**: Multi-condition rules, deduplication, escalation
- **RBAC & Compliance**: Role-based access control with audit trails
- **Comprehensive Integrations**: Grafana, ServiceNow, Jira, Slack, Teams

## 🏗️ Architecture

```
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   Data Sources  │───▶│  Transport Layer │───▶│ Parsing Engine  │
└─────────────────┘    └──────────────────┘    └─────────────────┘
                                                         │
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│   Storage Tiers │◀───│  Query Engine    │◀───│ Enrichment      │
└─────────────────┘    └──────────────────┘    └─────────────────┘
         │                       │
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│  ML Detection   │    │   Alerting       │    │  Integrations   │
└─────────────────┘    └──────────────────┘    └─────────────────┘
         │                       │                       │
┌─────────────────┐    ┌──────────────────┐    ┌─────────────────┐
│  Correlation    │    │   Web UI         │    │   External      │
│  Graph          │    │   & API          │    │   Systems       │
└─────────────────┘    └──────────────────┘    └─────────────────┘
```

## 🚦 Quick Start

### Prerequisites
- Node.js 18+ 
- Elasticsearch 8.x (for hot storage)
- Redis 6+ (for caching and streams)
- ClickHouse 22+ (optional, for warm storage)
- S3-compatible storage (optional, for cold storage)

### Installation

1. **Clone and Install Dependencies**
```bash
git clone <repository-url>
cd Cursor_AI_ProdAnalyzer
npm install
```

2. **Configure Environment**
```bash
# Copy and customize configuration
cp config/default.json config/local.json

# Set essential environment variables
export SESSION_SECRET="your-secure-session-secret-32-chars-min"
export ELASTICSEARCH_URL="http://localhost:9200"
export REDIS_HOST="localhost"
export REDIS_PORT="6379"
```

3. **Start the Application**
```bash
# Development mode
npm run dev

# Production mode
npm start
```

4. **Access the UI**
- Web Interface: http://localhost:3000
- Advanced Search: http://localhost:3000/advanced-search.html
- Default Login: admin / admin123

## ⚙️ Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `PORT` | HTTP server port | 3000 |
| `NODE_ENV` | Environment (development/production) | development |
| `SESSION_SECRET` | Session encryption secret | Required |
| `ELASTICSEARCH_URL` | Elasticsearch connection URL | http://localhost:9200 |
| `REDIS_HOST` | Redis host | localhost |
| `REDIS_PORT` | Redis port | 6379 |
| `CLICKHOUSE_HOST` | ClickHouse host (optional) | localhost |
| `KAFKA_BROKERS` | Kafka brokers (optional) | localhost:9092 |
| `S3_BUCKET` | S3 bucket for cold storage (optional) | logs-cold-storage |

### Configuration Files

Configuration is managed through JSON files in the `config/` directory:

- `default.json` - Base configuration
- `production.json` - Production overrides
- `local.json` - Local development overrides (not tracked in git)

### Key Configuration Sections

#### Storage Tiers
```json
{
  "storage": {
    "tiers": {
      "hot": {
        "enabled": true,
        "type": "elasticsearch",
        "retention": "7d"
      },
      "warm": {
        "enabled": false,
        "type": "clickhouse", 
        "retention": "30d"
      },
      "cold": {
        "enabled": false,
        "type": "s3",
        "retention": "365d"
      }
    }
  }
}
```

#### Integrations
```json
{
  "integrations": {
    "grafana": {
      "enabled": false,
      "url": "http://localhost:3000",
      "apiKey": "your-grafana-api-key"
    },
    "slack": {
      "enabled": false,
      "webhookUrl": "https://hooks.slack.com/...",
      "channel": "#alerts"
    }
  }
}
```

## 📊 Usage

### Log Ingestion

#### HTTP/JSON Ingestion
```bash
curl -X POST http://localhost:3000/api/logs/ingest \
  -H "Content-Type: application/json" \
  -d '{
    "timestamp": "2024-01-15T10:30:00Z",
    "level": "error",
    "service": "api-gateway",
    "message": "Database connection timeout",
    "metadata": {
      "userId": "12345",
      "requestId": "req-abc-123"
    }
  }'
```

#### OpenTelemetry Integration
```javascript
import { NodeSDK } from '@opentelemetry/sdk-node';
import { OTLPLogExporter } from '@opentelemetry/exporter-logs-otlp-http';

const sdk = new NodeSDK({
  logRecordProcessor: new BatchLogRecordProcessor(
    new OTLPLogExporter({
      url: 'http://localhost:8080/v1/logs'
    })
  )
});

sdk.start();
```

#### Syslog Integration
```bash
# Configure rsyslog to forward to log analyzer
echo "*.* @@localhost:514" >> /etc/rsyslog.conf
systemctl restart rsyslog
```

### Search and Analysis

#### Simple Search
```
error database timeout
```

#### Advanced Search (DSL)
```
level:error AND service:api-gateway AND timestamp:[now-1h TO now]
```

#### SQL Queries
```sql
SELECT service, COUNT(*) as error_count 
FROM logs 
WHERE level = 'error' AND timestamp > now() - interval '1 hour'
GROUP BY service 
ORDER BY error_count DESC
```

#### Regex Search
```regex
/ERROR.*database.*timeout/i
```

### Alerting

#### Create Alert Rule
```bash
curl -X POST http://localhost:3000/api/alerts/rules \
  -H "Content-Type: application/json" \
  -d '{
    "name": "High Error Rate",
    "conditions": [
      {
        "field": "level",
        "operator": "equals",
        "value": "error"
      }
    ],
    "threshold": {
      "count": 10,
      "timeWindow": "5m"
    },
    "notifications": ["slack", "email"]
  }'
```

## 🔧 API Reference

### Authentication
All API endpoints require authentication via Bearer token:
```bash
curl -H "Authorization: Bearer <token>" http://localhost:3000/api/...
```

### Core Endpoints

#### Search Logs
```
POST /api/search
{
  "query": "error database",
  "type": "simple|advanced|sql|regex",
  "filters": {
    "timeRange": "24h",
    "level": "error",
    "service": "api-gateway"
  },
  "page": 1,
  "pageSize": 50
}
```

#### Get Alerts
```
GET /api/alerts
GET /api/alerts/:id
POST /api/alerts/rules
PUT /api/alerts/rules/:id
DELETE /api/alerts/rules/:id
```

#### Service Topology
```
GET /api/topology/services
GET /api/topology/dependencies
GET /api/topology/health
```

#### System Status
```
GET /api/health
GET /api/metrics
GET /api/config/summary
```

## 🔐 Security

### Authentication & Authorization
- Session-based authentication with JWT tokens
- Role-based access control (RBAC) with predefined roles:
  - `super-admin`: Full system access
  - `admin`: Administrative access to most features  
  - `analyst`: Read access for analysis and investigation
  - `operator`: Basic operational access
  - `viewer`: Read-only access

### PII Protection
- Automatic PII detection for emails, SSNs, credit cards, phone numbers
- Configurable redaction modes: hash, mask, or remove
- Audit trail for all PII detection events

### Security Headers
- Helmet.js for security headers
- Rate limiting on API endpoints
- CORS configuration
- Session security with secure cookies

## 📈 Monitoring & Observability

### Built-in Metrics
- Log ingestion rate and volume
- Query performance and cache hit rates
- Alert firing rates and resolution times
- System resource utilization
- Integration health status

### Grafana Integration
Automatically creates dashboards for:
- Log Analytics Overview
- Service Health Monitoring  
- Alert Management
- System Performance

### Health Checks
```bash
# Application health
curl http://localhost:3000/api/health

# Component health
curl http://localhost:3000/api/health/detailed
```

## 🚀 Deployment

### Docker Deployment
```dockerfile
FROM node:18-alpine
WORKDIR /app
COPY package*.json ./
RUN npm ci --only=production
COPY . .
EXPOSE 3000
CMD ["npm", "start"]
```

### Docker Compose
```yaml
version: '3.8'
services:
  log-analyzer:
    build: .
    ports:
      - "3000:3000"
    environment:
      - NODE_ENV=production
      - ELASTICSEARCH_URL=http://elasticsearch:9200
      - REDIS_HOST=redis
    depends_on:
      - elasticsearch
      - redis
      
  elasticsearch:
    image: docker.elastic.co/elasticsearch/elasticsearch:8.11.0
    environment:
      - discovery.type=single-node
      - xpack.security.enabled=false
    ports:
      - "9200:9200"
      
  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"
```

### Kubernetes Deployment
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: log-analyzer
spec:
  replicas: 3
  selector:
    matchLabels:
      app: log-analyzer
  template:
    metadata:
      labels:
        app: log-analyzer
    spec:
      containers:
      - name: log-analyzer
        image: log-analyzer:latest
        ports:
        - containerPort: 3000
        env:
        - name: NODE_ENV
          value: "production"
        - name: ELASTICSEARCH_URL
          value: "http://elasticsearch:9200"
```

## 🔧 Development

### Project Structure
```
src/
├── core/
│   ├── ingestion/          # OTel collector, transport manager
│   ├── parsing/            # Enrichment engine, PII detection
│   ├── storage/            # Storage manager, tiering
│   ├── query/              # Query engine, DSL parser
│   ├── ml/                 # Anomaly detection, ML models
│   ├── correlation/        # Service topology, correlation
│   ├── alerting/           # Alert manager, notifications
│   ├── security/           # RBAC, authentication
│   ├── config/             # Configuration management
│   ├── integrations/       # External system integrations
│   └── utils/              # Shared utilities, logging
├── server.js               # Main application server
└── analyzer.js             # Legacy heuristic analyzer

public/                     # Static web assets
config/                     # Configuration files
data/                       # Sample data and logs
```

### Running Tests
```bash
# Unit tests
npm test

# Integration tests  
npm run test:integration

# Load tests
npm run test:load
```

### Development Scripts
```bash
# Start in development mode with hot reload
npm run dev

# Run linting
npm run lint

# Format code
npm run format

# Build for production
npm run build
```

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🆘 Support

### Documentation
- [API Documentation](docs/api.md)
- [Configuration Guide](docs/configuration.md)
- [Deployment Guide](docs/deployment.md)
- [Troubleshooting](docs/troubleshooting.md)

### Getting Help
- Create an issue for bugs or feature requests
- Check existing issues and discussions
- Review the troubleshooting guide

### Performance Tuning
- For high-volume environments (TB-PB scale), consider:
  - Horizontal scaling with load balancers
  - Dedicated Elasticsearch clusters
  - ClickHouse for analytical workloads
  - S3 for long-term archival
  - Redis clustering for caching

## 🔮 Roadmap

- [ ] Machine Learning model training interface
- [ ] Advanced correlation algorithms
- [ ] Custom dashboard builder
- [ ] Mobile application
- [ ] Advanced export formats
- [ ] Multi-tenant support
- [ ] Advanced compliance reporting
- [ ] Real-time collaboration features
