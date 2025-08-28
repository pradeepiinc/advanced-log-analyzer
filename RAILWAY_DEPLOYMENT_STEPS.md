# 🚀 Railway Deployment Steps - Advanced Production Log Analyzer

## Prerequisites
- Node.js 18+ installed
- Git repository (local or GitHub)
- Railway account (free at https://railway.app)

## Step-by-Step Deployment

### 1. Install Railway CLI
```powershell
npm install -g @railway/cli
```

### 2. Login to Railway
```powershell
railway login
```
This will open your browser for authentication.

### 3. Initialize Railway Project
```powershell
railway init
```
Choose "Empty Project" when prompted.

### 4. Set Environment Variables
```powershell
# Generate secure credentials
$SESSION_SECRET = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes((New-Guid).ToString() + (New-Guid).ToString()))
$ADMIN_PASS = [System.Convert]::ToBase64String([System.Security.Cryptography.RNGCryptoServiceProvider]::new().GetBytes(16))

# Set variables
railway variables set NODE_ENV=production
railway variables set SESSION_SECRET=$SESSION_SECRET
railway variables set ADMIN_USER=admin
railway variables set ADMIN_PASS=$ADMIN_PASS
railway variables set LOG_LEVEL=info
railway variables set PORT=3000
```

### 5. Add Redis Service
1. Go to https://railway.app/dashboard
2. Select your project
3. Click "New" → "Database" → "Add Redis"
4. Wait for Redis to deploy (2-3 minutes)

### 6. Configure Redis Connection
```powershell
railway variables set REDIS_HOST='${{Redis.RAILWAY_PRIVATE_DOMAIN}}'
railway variables set REDIS_PORT='${{Redis.RAILWAY_PORT}}'
```

### 7. Deploy Application
```powershell
railway up
```

### 8. Get Deployment URL
```powershell
railway domain
```

## Expected Output
After successful deployment, you'll see:
```
✅ Deployment live at: https://your-app-name.railway.app
```

## Access Your Application
- **Main Interface**: https://your-app-name.railway.app
- **Advanced Search**: https://your-app-name.railway.app/advanced-search.html
- **Health Check**: https://your-app-name.railway.app/api/health

## Login Credentials
- **Username**: admin
- **Password**: [Generated password from step 4]

## Verify Deployment
1. Visit the health check URL - should return `{"status":"ok"}`
2. Login to main interface with admin credentials
3. Test log ingestion via Advanced Search interface

## Troubleshooting
```powershell
# View logs
railway logs

# Check status
railway status

# Open Railway dashboard
railway open
```

## Cost Information
- **Free Tier**: 500 hours/month
- **Usage**: ~720 hours/month for 24/7 operation
- **Recommendation**: Upgrade to Hobby plan ($5/month) for production use

## Next Steps After Deployment
1. Save your admin password securely
2. Configure integrations (Slack, Grafana, etc.) via environment variables
3. Set up monitoring and alerts
4. Consider upgrading to paid plan for production workloads
