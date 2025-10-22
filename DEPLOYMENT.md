# Deployment Guide

This guide covers deploying the D.Watson Pharmacy Dashboard to various cloud platforms.

## Prerequisites

- Node.js 18+ installed locally
- Git repository with your code
- MongoDB Atlas account (or other MongoDB hosting)
- Accounts on your chosen deployment platform(s)

## Environment Variables

Before deploying, ensure you have the following environment variables configured:

```bash
NODE_ENV=production
PORT=5000
MONGODB_URI=mongodb+srv://username:password@cluster.mongodb.net/database
JWT_SECRET=your-super-secret-jwt-key
ADMIN_PASSWORD=your-admin-password
```

## Platform-Specific Deployment

### 1. Heroku Deployment

#### Option A: Using Heroku CLI
```bash
# Install Heroku CLI
# https://devcenter.heroku.com/articles/heroku-cli

# Login to Heroku
heroku login

# Create a new app
heroku create your-app-name

# Set environment variables
heroku config:set NODE_ENV=production
heroku config:set MONGODB_URI="your-mongodb-connection-string"
heroku config:set JWT_SECRET="your-jwt-secret"
heroku config:set ADMIN_PASSWORD="your-admin-password"

# Deploy
git push heroku main
```

#### Option B: Using GitHub Integration
1. Push your code to GitHub
2. Go to [Heroku Dashboard](https://dashboard.heroku.com)
3. Click "New" → "Create new app"
4. Connect your GitHub repository
5. Enable automatic deploys
6. Set environment variables in Settings → Config Vars
7. Deploy

#### Option C: One-Click Deploy
[![Deploy](https://www.herokucdn.com/deploy/button.svg)](https://heroku.com/deploy?template=https://github.com/yourusername/dwatson-pharmacy-dashboard)

### 2. Railway Deployment

#### Option A: Using Railway CLI
```bash
# Install Railway CLI
npm install -g @railway/cli

# Login to Railway
railway login

# Initialize project
railway init

# Set environment variables
railway variables set NODE_ENV=production
railway variables set MONGODB_URI="your-mongodb-connection-string"
railway variables set JWT_SECRET="your-jwt-secret"
railway variables set ADMIN_PASSWORD="your-admin-password"

# Deploy
railway up
```

#### Option B: Using GitHub Integration
1. Push your code to GitHub
2. Go to [Railway Dashboard](https://railway.app)
3. Click "New Project" → "Deploy from GitHub repo"
4. Select your repository
5. Set environment variables in Variables tab
6. Deploy

### 3. Koyeb Deployment

#### Option A: Using Koyeb CLI
```bash
# Install Koyeb CLI
# https://docs.koyeb.com/getting-started/cli

# Login to Koyeb
koyeb auth login

# Create secrets
koyeb secret create mongodb-uri "your-mongodb-connection-string"
koyeb secret create jwt-secret "your-jwt-secret"
koyeb secret create admin-password "your-admin-password"

# Deploy
koyeb service create --name dwatson-pharmacy-dashboard
```

#### Option B: Using Web Interface
1. Push your code to GitHub
2. Go to [Koyeb Dashboard](https://app.koyeb.com)
3. Click "Create Service"
4. Connect your GitHub repository
5. Configure environment variables
6. Deploy

### 4. Docker Deployment

#### Build and Run Locally
```bash
# Build the Docker image
docker build -t dwatson-pharmacy-dashboard .

# Run the container
docker run -p 5000:8080 \
  -e NODE_ENV=production \
  -e MONGODB_URI="your-mongodb-connection-string" \
  -e JWT_SECRET="your-jwt-secret" \
  -e ADMIN_PASSWORD="your-admin-password" \
  dwatson-pharmacy-dashboard
```

#### Deploy to Docker Hub
```bash
# Tag the image
docker tag dwatson-pharmacy-dashboard yourusername/dwatson-pharmacy-dashboard

# Push to Docker Hub
docker push yourusername/dwatson-pharmacy-dashboard
```

## Post-Deployment Configuration

### 1. Domain Configuration
- Configure your custom domain in your platform's dashboard
- Update CORS settings in `server/index.js` if needed
- Set up SSL certificates (usually automatic on most platforms)

### 2. Database Setup
- Ensure your MongoDB Atlas cluster allows connections from your deployment platform
- Add your deployment platform's IP ranges to MongoDB Atlas whitelist
- Test database connectivity using the health check endpoint

### 3. Monitoring
- Set up monitoring and alerting
- Configure log aggregation
- Set up uptime monitoring

## Health Checks

Your application includes health check endpoints:

- **Full Health Check**: `GET /api/health`
- **Simple Health Check**: `GET /health`

## Troubleshooting

### Common Issues

1. **CORS Errors**
   - Check your CORS configuration in `server/index.js`
   - Ensure your domain is in the allowed origins list

2. **Database Connection Issues**
   - Verify MongoDB URI is correct
   - Check MongoDB Atlas network access settings
   - Ensure database user has proper permissions

3. **Environment Variables**
   - Verify all required environment variables are set
   - Check for typos in variable names
   - Ensure values don't contain special characters that need escaping

4. **Build Failures**
   - Check Node.js version compatibility
   - Verify all dependencies are in package.json
   - Check for syntax errors in your code

### Logs and Debugging

- **Heroku**: `heroku logs --tail`
- **Railway**: `railway logs`
- **Koyeb**: Check logs in the web dashboard
- **Docker**: `docker logs container-name`

## Security Considerations

1. **Environment Variables**: Never commit sensitive data to version control
2. **JWT Secret**: Use a strong, random JWT secret in production
3. **Admin Password**: Use a strong admin password
4. **HTTPS**: Ensure your application is served over HTTPS
5. **Database**: Use MongoDB Atlas with proper security settings

## Performance Optimization

1. **Compression**: Already enabled in production
2. **Caching**: Consider adding Redis for session storage
3. **CDN**: Use a CDN for static assets
4. **Database Indexing**: Add proper indexes to your MongoDB collections
5. **Connection Pooling**: MongoDB driver handles this automatically

## Scaling

- **Horizontal Scaling**: Most platforms support auto-scaling
- **Database**: Consider MongoDB Atlas scaling options
- **Load Balancing**: Configure load balancers for high availability
- **Monitoring**: Set up proper monitoring and alerting

## Support

For deployment issues:
1. Check platform-specific documentation
2. Review application logs
3. Test locally with production environment variables
4. Contact platform support if needed
