@echo off
echo 🚀 Railway Deployment Script for Advanced Production Log Analyzer
echo.

echo Step 1: Installing Railway CLI...
npm install -g @railway/cli
if %errorlevel% neq 0 (
    echo ❌ Failed to install Railway CLI
    pause
    exit /b 1
)

echo.
echo Step 2: Login to Railway (this will open your browser)
echo Please complete the login process in your browser...
railway login
if %errorlevel% neq 0 (
    echo ❌ Railway login failed
    pause
    exit /b 1
)

echo.
echo Step 3: Creating Railway project...
railway init
if %errorlevel% neq 0 (
    echo ❌ Failed to initialize Railway project
    pause
    exit /b 1
)

echo.
echo Step 4: Setting up environment variables...
echo Generating secure session secret...
for /f "delims=" %%i in ('node -e "console.log(require('crypto').randomBytes(32).toString('base64'))"') do set SESSION_SECRET=%%i
for /f "delims=" %%i in ('node -e "console.log(require('crypto').randomBytes(16).toString('base64'))"') do set ADMIN_PASS=%%i

railway variables set NODE_ENV=production
railway variables set SESSION_SECRET=%SESSION_SECRET%
railway variables set ADMIN_USER=admin
railway variables set ADMIN_PASS=%ADMIN_PASS%
railway variables set LOG_LEVEL=info
railway variables set PORT=3000

echo.
echo Step 5: Adding Redis service...
echo Please add Redis service manually in Railway dashboard:
echo 1. Go to https://railway.app/dashboard
echo 2. Select your project
echo 3. Click "New" -> "Database" -> "Add Redis"
echo 4. Wait for Redis to deploy
echo.
echo Press any key when Redis is ready...
pause

echo.
echo Step 6: Deploying application...
railway up
if %errorlevel% neq 0 (
    echo ❌ Deployment failed
    pause
    exit /b 1
)

echo.
echo Step 7: Getting deployment URL...
railway domain

echo.
echo ✅ Deployment completed successfully!
echo.
echo 📋 Your credentials:
echo Username: admin
echo Password: %ADMIN_PASS%
echo.
echo 🔗 Access your application:
echo - Main Interface: Check the URL above
echo - Advanced Search: Add /advanced-search.html to the URL
echo - Health Check: Add /api/health to the URL
echo.
echo 📝 Save these credentials in a secure location!
pause
