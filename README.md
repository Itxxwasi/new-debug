# D.Watson Pharmacy Sales Dashboard

A comprehensive, production-ready sales dashboard application for D.Watson Pharmacy built with Express.js backend and vanilla JavaScript frontend. Designed for multi-branch pharmacy management with role-based access control.

## 🚀 Features

- **🔐 Secure Authentication**: JWT-based authentication with role-based access control
- **💰 Sales Management**: Complete sales tracking and management system
- **🏢 Multi-Branch Support**: Manage multiple pharmacy branches
- **📊 Category Management**: Organize products by categories
- **👥 User Management**: Role-based user management system
- **📈 Reports & Analytics**: Generate comprehensive sales reports
- **📱 Responsive Design**: Works seamlessly on desktop and mobile devices
- **🔒 Production Ready**: Security headers, compression, error handling
- **☁️ Cloud Deployable**: Ready for Heroku, Railway, Koyeb, and Docker

## 🛠 Technology Stack

- **Backend**: Node.js, Express.js, MongoDB, Mongoose
- **Frontend**: Vanilla JavaScript, HTML5, CSS3, Bootstrap 5
- **Authentication**: JWT (JSON Web Tokens) with bcrypt
- **Database**: MongoDB Atlas
- **Styling**: Bootstrap 5, Font Awesome, Google Fonts
- **Security**: Helmet.js, CORS, Input sanitization, Rate limiting
- **Performance**: Compression, Production optimizations

## 🚀 Quick Start

### Prerequisites

- Node.js 18+ 
- MongoDB Atlas account
- Git

### Local Development

1. **Clone the repository:**
```bash
git clone https://github.com/yourusername/dwatson-pharmacy-dashboard.git
cd dwatson-pharmacy-dashboard
```

2. **Install dependencies:**
```bash
npm install
```

3. **Set up environment variables:**
```bash
cp env.example .env
# Edit .env with your configuration
```

4. **Start the development server:**
```bash
npm run dev
```

5. **Open your browser:**
Navigate to `http://localhost:5000`

## 🔧 Environment Variables

Create a `.env` file with the following variables:

```env
NODE_ENV=development
PORT=5000
MONGODB_URI=mongodb+srv://username:password@cluster.mongodb.net/database
JWT_SECRET=your-super-secret-jwt-key
ADMIN_PASSWORD=your-admin-password
```

## 📡 API Endpoints

### Authentication
- `POST /api/auth/login` - User login
- `POST /api/auth/logout` - User logout  
- `POST /api/auth/signup` - User registration
- `GET /api/auth/me` - Get current user info

### Sales Management
- `GET /api/sales` - Get all sales (with filtering)
- `POST /api/sales` - Create new sale
- `PUT /api/sales/:id` - Update sale
- `DELETE /api/sales/:id` - Delete sale

### Branch Management
- `GET /api/branches` - Get all branches
- `POST /api/branches` - Create new branch
- `PUT /api/branches/:id` - Update branch
- `DELETE /api/branches/:id` - Delete branch

### Category Management
- `GET /api/categories` - Get all categories
- `POST /api/categories` - Create new category
- `PUT /api/categories/:id` - Update category
- `DELETE /api/categories/:id` - Delete category

### User Management
- `GET /api/users` - Get all users
- `POST /api/users` - Create new user
- `PUT /api/users/:id` - Update user
- `DELETE /api/users/:id` - Delete user

### System
- `GET /api/health` - Comprehensive health check
- `GET /health` - Simple health check for load balancers

## 🔑 Default Login Credentials

- **Username**: `admin`
- **Password**: `admin123`

## ☁️ Deployment

This application is ready for deployment on multiple platforms:

### Heroku
[![Deploy](https://www.herokucdn.com/deploy/button.svg)](https://heroku.com/deploy?template=https://github.com/Itxxwasi/DWATSON-DB.git)

#### Option A: One-Click Deploy
Click the button above to deploy directly to Heroku.

#### Option B: CLI Deployment
```powershell
heroku login
heroku create your-app-name
heroku git:remote -a your-app-name
git push heroku main
heroku config:set MONGODB_URI="your_production_mongo_uri"
heroku config:set JWT_SECRET="your_jwt_secret"
heroku config:set ADMIN_PASSWORD="your_admin_password"
heroku ps:scale web=1
heroku open
```

### Railway
[![Deploy on Railway](https://railway.app/button.svg)](https://railway.app/template/your-template-id)

### Koyeb
[![Deploy to Koyeb](https://www.koyeb.com/static/images/deploy/button.svg)](https://app.koyeb.com/deploy?type=git&repository=your-repo)

### Docker
```bash
docker build -t dwatson-pharmacy-dashboard .
docker run -p 5000:8080 dwatson-pharmacy-dashboard
```

For detailed deployment instructions, see [DEPLOYMENT.md](./DEPLOYMENT.md).

## 🔒 Security Features

- **JWT Authentication**: Secure token-based authentication
- **Password Hashing**: bcrypt for secure password storage
- **CORS Protection**: Configurable cross-origin resource sharing
- **Rate Limiting**: Protection against brute force attacks
- **Input Sanitization**: XSS and injection attack prevention
- **Security Headers**: Helmet.js for security headers
- **Environment Variables**: Sensitive data protection

## 📊 Production Features

- **Compression**: Gzip compression for better performance
- **Error Handling**: Comprehensive error handling and logging
- **Health Checks**: Built-in health monitoring endpoints
- **Graceful Shutdown**: Proper process termination handling
- **Database Seeding**: Automatic initial data setup
- **Logging**: Structured logging with Morgan

## 🏗 Project Structure

```
dwatson-pharmacy-dashboard/
├── server/
│   └── index.js              # Main server file
├── index.html                # Frontend application
├── package.json              # Dependencies and scripts
├── Procfile                  # Heroku deployment config
├── app.json                  # Heroku app configuration
├── railway.json              # Railway deployment config
├── koyeb.yaml                # Koyeb deployment config
├── Dockerfile                # Docker configuration
├── DEPLOYMENT.md             # Deployment guide
└── README.md                 # This file
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

- **Email**: support@dwatson.com
- **Issues**: [GitHub Issues](https://github.com/yourusername/dwatson-pharmacy-dashboard/issues)
- **Documentation**: [DEPLOYMENT.md](./DEPLOYMENT.md)

## 🎯 Roadmap

- [ ] Real-time notifications
- [ ] Advanced reporting with charts
- [ ] Inventory management
- [ ] Customer management
- [ ] Payment integration
- [ ] Mobile app
- [ ] API documentation with Swagger

---

**Built with ❤️ for D.Watson Pharmacy**