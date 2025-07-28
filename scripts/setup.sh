#!/bin/bash

# Complete Setup Script for Expense Tracker
# This script automates the entire setup process

echo "🚀 Starting Expense Tracker Setup..."
echo "=================================="

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${GREEN}✅ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

print_error() {
    echo -e "${RED}❌ $1${NC}"
}

print_info() {
    echo -e "${BLUE}ℹ️  $1${NC}"
}

# Check if required software is installed
check_requirements() {
    print_info "Checking system requirements..."
    
    # Check Node.js
    if command -v node &> /dev/null; then
        NODE_VERSION=$(node --version)
        print_status "Node.js is installed: $NODE_VERSION"
    else
        print_error "Node.js is not installed. Please install from https://nodejs.org/"
        exit 1
    fi
    
    # Check Python
    if command -v python3 &> /dev/null; then
        PYTHON_VERSION=$(python3 --version)
        print_status "Python is installed: $PYTHON_VERSION"
    elif command -v python &> /dev/null; then
        PYTHON_VERSION=$(python --version)
        print_status "Python is installed: $PYTHON_VERSION"
    else
        print_error "Python is not installed. Please install from https://python.org/"
        exit 1
    fi
    
    # Check MySQL
    if command -v mysql &> /dev/null; then
        print_status "MySQL is installed"
    else
        print_warning "MySQL not found. Please install MySQL Server"
        print_info "Download from: https://dev.mysql.com/downloads/mysql/"
    fi
    
    # Check Git
    if command -v git &> /dev/null; then
        print_status "Git is installed"
    else
        print_error "Git is not installed. Please install from https://git-scm.com/"
        exit 1
    fi
}

# Create project structure
create_structure() {
    print_info "Creating project structure..."
    
    mkdir -p expense-tracker-app/{frontend,backend,database,scripts}
    cd expense-tracker-app
    
    print_status "Project structure created"
}

# Setup frontend
setup_frontend() {
    print_info "Setting up frontend (Next.js)..."
    
    cd frontend
    
    # Create Next.js app
    npx create-next-app@latest . --typescript --tailwind --eslint --app --src-dir --import-alias "@/*" --yes
    
    # Install additional dependencies
    npm install @radix-ui/react-dialog @radix-ui/react-select @radix-ui/react-tabs lucide-react chart.js react-chartjs-2 class-variance-authority clsx tailwind-merge
    
    # Setup shadcn/ui
    npx shadcn@latest init --yes --style default --base-color slate --css-variables
    npx shadcn@latest add button card input label tabs dialog select badge toast
    
    cd ..
    print_status "Frontend setup completed"
}

# Setup backend
setup_backend() {
    print_info "Setting up backend (Flask)..."
    
    cd backend
    
    # Create virtual environment
    python3 -m venv venv 2>/dev/null || python -m venv venv
    
    # Activate virtual environment
    if [[ "$OSTYPE" == "msys" || "$OSTYPE" == "win32" ]]; then
        source venv/Scripts/activate
    else
        source venv/bin/activate
    fi
    
    # Install Python dependencies
    pip install Flask Flask-SQLAlchemy Flask-Bcrypt Flask-JWT-Extended Flask-Mail Flask-CORS python-dotenv PyMySQL cryptography
    
    # Create requirements file
    pip freeze > requirements.txt
    
    cd ..
    print_status "Backend setup completed"
}

# Create configuration files
create_config() {
    print_info "Creating configuration files..."
    
    # Create .env file for backend
    cat > backend/.env << EOL
# Database Configuration
DATABASE_URL=mysql://root:your_mysql_password@localhost/expense_tracker

# JWT Configuration
SECRET_KEY=your-super-secret-key-change-this-in-production-$(date +%s)
JWT_SECRET_KEY=your-jwt-secret-key-change-this-too-$(date +%s)

# Email Configuration (Gmail example)
MAIL_SERVER=smtp.gmail.com
MAIL_PORT=587
MAIL_USERNAME=your-email@gmail.com
MAIL_PASSWORD=your-gmail-app-password
MAIL_DEFAULT_SENDER=your-email@gmail.com

# Environment
FLASK_ENV=development
FLASK_DEBUG=1
EOL

    print_status "Configuration files created"
    print_warning "Please update the .env file with your actual credentials"
}

# Create database setup script
create_db_script() {
    print_info "Creating database setup script..."
    
    cat > database/setup.sql << EOL
-- Create database
CREATE DATABASE IF NOT EXISTS expense_tracker;
USE expense_tracker;

-- Users table
CREATE TABLE user (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    email VARCHAR(120) UNIQUE NOT NULL,
    password_hash VARCHAR(128) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Expenses table
CREATE TABLE expense (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    category VARCHAR(50) NOT NULL,
    amount DECIMAL(10, 2) NOT NULL,
    description TEXT,
    date DATE NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES user(id) ON DELETE CASCADE
);

-- Income table
CREATE TABLE income (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    amount DECIMAL(10, 2) NOT NULL,
    month INT NOT NULL CHECK (month >= 1 AND month <= 12),
    year INT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES user(id) ON DELETE CASCADE,
    UNIQUE KEY unique_user_month_year (user_id, month, year)
);

-- Monthly limits table
CREATE TABLE monthly_limit (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    limit_amount DECIMAL(10, 2) NOT NULL,
    month INT NOT NULL CHECK (month >= 1 AND month <= 12),
    year INT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES user(id) ON DELETE CASCADE,
    UNIQUE KEY unique_user_limit_month_year (user_id, month, year)
);

-- Indexes for better performance
CREATE INDEX idx_expense_user_date ON expense(user_id, date);
CREATE INDEX idx_expense_category ON expense(category);
CREATE INDEX idx_income_user_month_year ON income(user_id, month, year);
CREATE INDEX idx_monthly_limit_user_month_year ON monthly_limit(user_id, month, year);
EOL

    print_status "Database setup script created"
}

# Create startup scripts
create_startup_scripts() {
    print_info "Creating startup scripts..."
    
    # Backend startup script
    cat > scripts/start-backend.sh << EOL
#!/bin/bash
cd backend
if [[ "\$OSTYPE" == "msys" || "\$OSTYPE" == "win32" ]]; then
    source venv/Scripts/activate
else
    source venv/bin/activate
fi
python app.py
EOL

    # Frontend startup script
    cat > scripts/start-frontend.sh << EOL
#!/bin/bash
cd frontend
npm run dev
EOL

    # Make scripts executable
    chmod +x scripts/start-backend.sh
    chmod +x scripts/start-frontend.sh
    
    print_status "Startup scripts created"
}

# Main setup function
main() {
    echo "🎯 Expense Tracker Complete Setup"
    echo "================================="
    echo ""
    
    check_requirements
    echo ""
    
    create_structure
    echo ""
    
    setup_frontend
    echo ""
    
    setup_backend
    echo ""
    
    create_config
    echo ""
    
    create_db_script
    echo ""
    
    create_startup_scripts
    echo ""
    
    print_status "Setup completed successfully! 🎉"
    echo ""
    echo "📋 Next Steps:"
    echo "1. Update backend/.env with your MySQL password and Gmail credentials"
    echo "2. Run database setup: mysql -u root -p < database/setup.sql"
    echo "3. Start backend: ./scripts/start-backend.sh"
    echo "4. Start frontend: ./scripts/start-frontend.sh (in new terminal)"
    echo "5. Open http://localhost:3000 in your browser"
    echo ""
    print_info "For detailed instructions, see COMPLETE_SETUP_GUIDE.md"
}

# Run main function
main
