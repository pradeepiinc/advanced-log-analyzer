# 🚀 Deployment Guide - Advanced Production Log Analyzer

This guide provides multiple options for deploying the Advanced Production Log Analyzer to open-source cloud infrastructure.

## 🎯 Quick Deploy Options

### Option 1: Railway (Recommended)
**Free tier: 500 hours/month, $5/month for hobby plan**

1. **Fork/Clone the repository**
2. **Connect to Railway:**
   ```bash
   # Install Railway CLI
   npm install -g @railway/cli
   
   # Login to Railway
   railway login
   
   # Deploy from current directory
   railway up
   ```

3. **Set Environment Variables in Railway Dashboard:**
   ```
   NODE_ENV=production
   SESSION_SECRET=your-secure-32-char-secret
   ADMIN_USER=admin
   ADMIN_PASS=your-secure-password
   LOG_LEVEL=info
   ```

4. **Add Services:**
   - Add Redis service from Railway marketplace
   - Add PostgreSQL service (for metadata storage)
   - Configure environment variables to connect services

### Option 2: Render
**Free tier available, $7/month for starter plan**

1. **Connect GitHub repository to Render**
2. **Create Web Service:**
   - Build Command: `npm ci`
   - Start Command: `npm start`
   - Environment: `Node`

3. **Add Environment Variables:**
   ```
   NODE_ENV=production
   SESSION_SECRET=generate-secure-secret
   ADMIN_USER=admin
   ADMIN_PASS=generate-secure-password
   PORT=10000
   ```

4. **Add Services:**
   - Create Redis service
   - Create PostgreSQL database
   - Update connection strings in environment variables

### Option 3: Docker Compose (Self-hosted)
**Run on any VPS or local machine**

```bash
# Clone repository
git clone <your-repo-url>
cd Cursor_AI_ProdAnalyzer

# Update environment variables in docker-compose.yml
# Generate secure SESSION_SECRET (32+ characters)
export SESSION_SECRET=$(openssl rand -base64 32)

# Start all services
docker-compose up -d

# Check status
docker-compose ps

# View logs
docker-compose logs -f app
```

### Option 4: Vercel (Frontend + Serverless)
**Free tier: 100GB bandwidth, hobby plan $20/month**

```bash
# Install Vercel CLI
npm install -g vercel

# Deploy
vercel

# Set environment variables
vercel env add SESSION_SECRET
vercel env add ADMIN_USER
vercel env add ADMIN_PASS
```

Note: Vercel is best for the frontend. You'll need external services for Elasticsearch and Redis.

## 🗄️ Database & Storage Setup

### Elasticsearch Options

#### 1. Elastic Cloud (Free tier: 14 days)
```bash
# Sign up at https://cloud.elastic.co
# Get connection URL and set:
export ELASTICSEARCH_URL="https://your-cluster.es.region.cloud.es.io:9243"
```

#### 2. Bonsai Elasticsearch (Free tier: 35MB)
```bash
# Sign up at https://bonsai.io
# Add to your deployment platform
export ELASTICSEARCH_URL="https://user:pass@your-cluster.bonsai.io"
```

#### 3. Self-hosted Elasticsearch
```yaml
# Add to docker-compose.yml
elasticsearch:
  image: docker.elastic.co/elasticsearch/elasticsearch:8.11.0
  environment:
    - discovery.type=single-node
    - xpack.security.enabled=false
```

### Redis Options

#### 1. Railway Redis (Free tier included)
- Add Redis service in Railway dashboard
- Connection string automatically provided

#### 2. Render Redis (Free tier: 25MB)
- Add Redis service in Render dashboard
- Get connection details

#### 3. Upstash Redis (Free tier: 10K requests/day)
```bash
# Sign up at https://upstash.com
export REDIS_URL="redis://user:pass@host:port"
```

## 🔧 Environment Variables

### Required Variables
```bash
NODE_ENV=production
PORT=3000
SESSION_SECRET=your-secure-32-char-secret-here
ADMIN_USER=admin
ADMIN_PASS=your-secure-password
```

### Optional Variables
```bash
# Logging
LOG_LEVEL=info

# Storage
ELASTICSEARCH_URL=http://localhost:9200
REDIS_HOST=localhost
REDIS_PORT=6379

# Features (set to true to enable)
CLICKHOUSE_ENABLED=false
KAFKA_ENABLED=false
S3_ENABLED=false

# Integrations
SLACK_WEBHOOK_URL=https://hooks.slack.com/...
GRAFANA_URL=http://localhost:3000
GRAFANA_API_KEY=your-api-key
```

## 🚀 Step-by-Step Railway Deployment

### 1. Prepare Repository
```bash
# Ensure all files are committed
git add .
git commit -m "Prepare for deployment"
git push origin main
```

### 2. Deploy to Railway
```bash
# Install Railway CLI
npm install -g @railway/cli

# Login
railway login

# Initialize project
railway init

# Deploy
railway up
```

### 3. Configure Services
1. **Add Redis:**
   - Go to Railway dashboard
   - Click "New" → "Database" → "Add Redis"
   - Note the connection details

2. **Set Environment Variables:**
   ```bash
   railway variables set NODE_ENV=production
   railway variables set SESSION_SECRET=$(openssl rand -base64 32)
   railway variables set ADMIN_USER=admin
   railway variables set ADMIN_PASS=$(openssl rand -base64 16)
   ```

3. **Configure Redis Connection:**
   ```bash
   railway variables set REDIS_HOST=${{Redis.RAILWAY_PRIVATE_DOMAIN}}
   railway variables set REDIS_PORT=${{Redis.RAILWAY_PORT}}
   ```

### 4. Deploy and Test
```bash
# Redeploy with new variables
railway up

# Get deployment URL
railway domain

# Test deployment
curl https://your-app.railway.app/api/health
```

## 🔍 Verification Steps

### 1. Health Check
```bash
curl https://your-deployed-app.com/api/health
# Should return: {"status":"ok","timestamp":"..."}
```

### 2. Login Test
1. Visit: `https://your-deployed-app.com`
2. Login with admin credentials
3. Check dashboard loads

### 3. Log Ingestion Test
```bash
curl -X POST https://your-deployed-app.com/api/logs/ingest \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -d '{
    "timestamp": "'$(date -u +%Y-%m-%dT%H:%M:%S.%3NZ)'",
    "level": "info",
    "message": "Test log from deployment",
    "service": "deployment-test"
  }'
```

### 4. Search Test
1. Visit: `https://your-deployed-app.com/advanced-search.html`
2. Search for "deployment-test"
3. Verify log appears in results

## 💰 Cost Estimates

### Free Tier Options
- **Railway**: 500 hours/month free
- **Render**: Free tier with limitations
- **Vercel**: 100GB bandwidth free
- **Upstash Redis**: 10K requests/day free
- **Bonsai Elasticsearch**: 35MB free

### Paid Options (Monthly)
- **Railway Hobby**: $5/month
- **Render Starter**: $7/month
- **Vercel Pro**: $20/month
- **Elastic Cloud**: $16/month (Basic)
- **Digital Ocean Droplet**: $5/month (1GB RAM)

## 🛠️ Troubleshooting

### Common Issues

#### 1. Memory Limits
```bash
# Reduce Elasticsearch memory usage
export ES_JAVA_OPTS="-Xms256m -Xmx256m"
```

#### 2. Connection Timeouts
```bash
# Increase timeout values
export REQUEST_TIMEOUT=60000
export ELASTICSEARCH_TIMEOUT=30000
```

#### 3. Port Issues
```bash
# Use environment PORT variable
export PORT=${PORT:-3000}
```

### Debug Commands
```bash
# Check logs
railway logs
# or
docker-compose logs -f app

# Check environment variables
railway variables
# or
printenv | grep -E "(NODE_ENV|SESSION_SECRET|ELASTICSEARCH)"

# Test connections
curl -v https://your-app.com/api/health
```

## 🔒 Security Considerations

### Production Checklist
- [ ] Generate secure SESSION_SECRET (32+ characters)
- [ ] Use strong admin password
- [ ] Enable HTTPS (automatic on most platforms)
- [ ] Configure CORS origins
- [ ] Set up rate limiting
- [ ] Enable security headers
- [ ] Configure firewall rules (if self-hosting)

### Environment Security
```bash
# Generate secure secrets
openssl rand -base64 32  # For SESSION_SECRET
openssl rand -base64 16  # For passwords
```

## 📊 Monitoring

### Built-in Monitoring
- Health endpoint: `/api/health`
- Metrics endpoint: `/api/metrics`
- Status dashboard: `/api/status`

### External Monitoring
- **Uptime Robot**: Free uptime monitoring
- **Pingdom**: Website monitoring
- **DataDog**: APM (free tier available)

## 🎉 Success!

Once deployed, your Advanced Production Log Analyzer will be available at:
- **Main Interface**: `https://your-app.com`
- **Advanced Search**: `https://your-app.com/advanced-search.html`
- **API Documentation**: `https://your-app.com/api/docs`

Default login: `admin` / `your-configured-password`

## 📞 Support

If you encounter issues:
1. Check the troubleshooting section above
2. Review application logs
3. Verify environment variables
4. Test individual components

The system is designed to gracefully degrade when external services (Elasticsearch, Redis) are unavailable, so basic functionality should work even with minimal configuration.
