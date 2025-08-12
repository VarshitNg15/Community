# Community Issue Management System

A Flask-based web application for community issue reporting, voting, and management. This platform allows community members to report local issues, vote on important problems, and collaborate with administrators to resolve community concerns.

## 🚀 Features

### For Community Members (Users)
- **Issue Reporting**: Submit community issues with descriptions, categories, and photo uploads
- **Location Tracking**: Automatically capture GPS coordinates for issue locations
- **Voting System**: Vote on issues to prioritize community concerns
- **Suggestions**: Provide suggestions and feedback on reported issues
- **Issue Tracking**: View pending and completed issues
- **User Dashboard**: Personalized dashboard showing your reported issues

### For Administrators
- **Admin Dashboard**: Comprehensive overview of all community issues
- **Issue Management**: Update issue status, add execution plans, and mark issues as completed
- **Report Review**: Handle user reports about inappropriate content
- **Location Viewing**: View exact locations of reported issues
- **Analytics**: Track voting patterns and community engagement

## 🛠️ Technology Stack

- **Backend**: Flask (Python web framework)
- **Database**: MongoDB with PyMongo
- **Authentication**: Flask-Login with Bcrypt password hashing
- **File Upload**: Werkzeug for secure file handling
- **Frontend**: HTML templates with Bootstrap styling

## 📋 Prerequisites

- Python 3.7+
- MongoDB database
- pip (Python package manager)

## 🚀 Installation & Setup

### 1. Clone the Repository
```bash
git clone <repository-url>
cd Community
```

### 2. Create Virtual Environment
```bash
python -m venv venv
# On Windows
venv\Scripts\activate
# On macOS/Linux
source venv/bin/activate
```

### 3. Install Dependencies
```bash
pip install -r requirements.txt
```

### 4. Configure MongoDB
1. Set up a MongoDB database (local or cloud)
2. Update the MongoDB URI in `app.py`:
```python
app.config['MONGO_URI'] = 'mongodb://localhost:27017/community_db'
```

### 5. Configure Application
Update the following configurations in `app.py`:
```python
app.config['SECRET_KEY'] = 'your-secret-key-here'
app.config['UPLOAD_FOLDER'] = 'static/uploads/'
```

### 6. Create Upload Directory
```bash
mkdir static/uploads
```

### 7. Run the Application
```bash
python app.py
```

The application will be available at `http://localhost:5000`

## 📁 Project Structure

```
Community/
├── app.py                 # Main Flask application
├── models.py             # Database schema definitions
├── requirements.txt      # Python dependencies
├── static/
│   └── uploads/         # User uploaded images
├── templates/           # HTML templates
│   ├── base.html       # Base template
│   ├── home.html       # Login/Register page
│   ├── user_dashboard.html
│   ├── admin_dashboard.html
│   └── ...            # Other template files
└── README.md           # This file
```

## 🔐 User Roles

### User
- Report community issues
- Vote on issues
- Provide suggestions
- Track personal issues

### Admin
- Manage all community issues
- Update issue status and plans
- Review user reports
- View issue locations

## 🗄️ Database Schema

### Users Collection
```javascript
{
  _id: ObjectId,
  username: String,
  password: String (hashed),
  role: String ('user' or 'admin')
}
```

### Issues Collection
```javascript
{
  _id: ObjectId,
  user_id: ObjectId,
  description: String,
  category: String,
  photo_filename: String,
  latitude: Number,
  longitude: Number,
  created_at: Date,
  votes: Number,
  suggestions: [ObjectId],
  plan_of_execution: String,
  status: String
}
```

### Votes Collection
```javascript
{
  _id: ObjectId,
  user_id: ObjectId,
  issue_id: ObjectId,
  created_at: Date
}
```

### Suggestions Collection
```javascript
{
  _id: ObjectId,
  user_id: ObjectId,
  issue_id: ObjectId,
  suggestion: String,
  created_at: Date
}
```

### Reports Collection
```javascript
{
  _id: ObjectId,
  reporter_id: ObjectId,
  issue_id: ObjectId,
  reason: String,
  created_at: Date,
  status: String
}
```

## 🎯 Key Features Explained

### Issue Reporting
- Users can submit issues with descriptions and categories
- Photo uploads are supported (PNG, JPG, JPEG, GIF)
- GPS coordinates are automatically captured
- Issues are stored with timestamps and user information

### Voting System
- Users can vote on community issues
- One vote per user per issue
- Vote counts help prioritize community concerns
- Real-time vote tracking

### Admin Management
- Comprehensive dashboard showing all issues
- Ability to update issue status and add execution plans
- Review system for handling inappropriate content
- Location viewing for precise issue identification

### Security Features
- Password hashing with Bcrypt
- User authentication with Flask-Login
- Role-based access control
- Secure file upload handling

## 🔧 Configuration Options

### Environment Variables
You can set these environment variables for production:
- `MONGO_URI`: MongoDB connection string
- `SECRET_KEY`: Flask secret key
- `UPLOAD_FOLDER`: Path for file uploads

### File Upload Settings
- Supported formats: PNG, JPG, JPEG, GIF
- Upload directory: `static/uploads/`
- Secure filename handling

## 🚀 Deployment

### Local Development
```bash
python app.py
```

### Production Deployment
1. Set up a production MongoDB instance
2. Configure environment variables
3. Use a production WSGI server (Gunicorn, uWSGI)
4. Set up reverse proxy (Nginx, Apache)
5. Configure SSL certificates

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

## 📝 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🆘 Support

For support and questions:
- Create an issue in the repository
- Contact the development team
- Check the documentation

## 🔄 Version History

- **v1.0.0**: Initial release with basic issue reporting and admin management
- Core features: user registration, issue reporting, voting, admin dashboard

---

**Built with ❤️ for community engagement and local governance** 