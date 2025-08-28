#!/bin/bash

echo "🚀 Railway Deployment Script for Advanced Production Log Analyzer"
echo

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${BLUE}$1${NC}"
}

print_success() {
    echo -e "${GREEN}✅ $1${NC}"
}

print_error() {
    echo -e "${RED}❌ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

# Check if Node.js is installed
if ! command -v node &> /dev/null; then
    print_error "Node.js is not installed. Please install Node.js 18+ first."
    exit 1
fi

print_status "Step 1: Installing Railway CLI..."
npm install -g @railway/cli
if [ $? -ne 0 ]; then
    print_error "Failed to install Railway CLI"
    exit 1
fi
print_success "Railway CLI installed"

print_status "Step 2: Login to Railway (this will open your browser)"
echo "Please complete the login process in your browser..."
railway login
if [ $? -ne 0 ]; then
    print_error "Railway login failed"
    exit 1
fi
print_success "Railway login successful"

print_status "Step 3: Creating Railway project..."
railway init
if [ $? -ne 0 ]; then
    print_error "Failed to initialize Railway project"
    exit 1
fi
print_success "Railway project created"

print_status "Step 4: Setting up environment variables..."
echo "Generating secure credentials..."

# Generate secure session secret and admin password
SESSION_SECRET=$(node -e "console.log(require('crypto').randomBytes(32).toString('base64'))")
ADMIN_PASS=$(node -e "console.log(require('crypto').randomBytes(16).toString('base64'))")

# Set environment variables
railway variables set NODE_ENV=production
railway variables set SESSION_SECRET="$SESSION_SECRET"
railway variables set ADMIN_USER=admin
railway variables set ADMIN_PASS="$ADMIN_PASS"
railway variables set LOG_LEVEL=info
railway variables set PORT=3000

print_success "Environment variables configured"

print_status "Step 5: Adding Redis service..."
print_warning "Please add Redis service manually in Railway dashboard:"
echo "1. Go to https://railway.app/dashboard"
echo "2. Select your project"
echo "3. Click 'New' -> 'Database' -> 'Add Redis'"
echo "4. Wait for Redis to deploy"
echo
read -p "Press Enter when Redis is ready..."

print_status "Step 6: Configuring Redis connection..."
# Note: Railway automatically provides Redis connection via environment variables
railway variables set REDIS_HOST='${{Redis.RAILWAY_PRIVATE_DOMAIN}}'
railway variables set REDIS_PORT='${{Redis.RAILWAY_PORT}}'
railway variables set REDIS_URL='${{Redis.REDIS_URL}}'

print_success "Redis connection configured"

print_status "Step 7: Deploying application..."
railway up
if [ $? -ne 0 ]; then
    print_error "Deployment failed"
    exit 1
fi
print_success "Application deployed successfully"

print_status "Step 8: Getting deployment URL..."
DEPLOYMENT_URL=$(railway domain)

echo
print_success "Deployment completed successfully!"
echo
echo "📋 Your credentials:"
echo "Username: admin"
echo "Password: $ADMIN_PASS"
echo
echo "🔗 Access your application:"
echo "- Main Interface: $DEPLOYMENT_URL"
echo "- Advanced Search: $DEPLOYMENT_URL/advanced-search.html"
echo "- Health Check: $DEPLOYMENT_URL/api/health"
echo
print_warning "Save these credentials in a secure location!"
echo
echo "🔧 To manage your deployment:"
echo "railway logs     # View application logs"
echo "railway open     # Open Railway dashboard"
echo "railway status   # Check deployment status"
