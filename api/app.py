from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from flask_mail import Mail, Message
from flask_cors import CORS
from datetime import datetime, timedelta
import os
from dotenv import load_dotenv

load_dotenv()

app = Flask(__name__)

# Configuration
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'expense-tracker-secret-key-2025-change-this-in-production')
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv('DATABASE_URL', 'mysql://root:password@localhost/expense_tracker')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# JWT Configuration
app.config['JWT_SECRET_KEY'] = os.getenv('JWT_SECRET_KEY', 'jwt-expense-tracker-secret-2025-change-this-too')
app.config['JWT_ACCESS_TOKEN_EXPIRES'] = timedelta(days=7)
app.config['JWT_ALGORITHM'] = 'HS256'

# Email configuration - FIXED VERSION
app.config['MAIL_SERVER'] = os.getenv('MAIL_SERVER', 'smtp.gmail.com')
app.config['MAIL_PORT'] = int(os.getenv('MAIL_PORT', 587))
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False
app.config['MAIL_USERNAME'] = os.getenv('MAIL_USERNAME')
app.config['MAIL_PASSWORD'] = os.getenv('MAIL_PASSWORD')
app.config['MAIL_DEFAULT_SENDER'] = os.getenv('MAIL_DEFAULT_SENDER')

# Debug email configuration
print(f"DEBUG: Email Config - Server: {app.config['MAIL_SERVER']}")
print(f"DEBUG: Email Config - Port: {app.config['MAIL_PORT']}")
print(f"DEBUG: Email Config - Username: {app.config['MAIL_USERNAME']}")
print(f"DEBUG: Email Config - Default Sender: {app.config['MAIL_DEFAULT_SENDER']}")
print(f"DEBUG: Email Config - Password Set: {'Yes' if app.config['MAIL_PASSWORD'] else 'No'}")

# Initialize extensions
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)
mail = Mail(app)

# Updated CORS for production
CORS(app, origins=["*"], supports_credentials=True)

# JWT Error Handlers
@jwt.expired_token_loader
def expired_token_callback(jwt_header, jwt_payload):
    return jsonify({'message': 'Token has expired', 'error': 'token_expired'}), 401

@jwt.invalid_token_loader
def invalid_token_callback(error):
    return jsonify({'message': 'Invalid token', 'error': 'token_invalid'}), 401

@jwt.unauthorized_loader
def missing_token_callback(error):
    return jsonify({'message': 'Authorization token is required', 'error': 'token_missing'}), 401

# Models
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    
    # Relationships
    expenses = db.relationship('Expense', backref='user', lazy=True, cascade='all, delete-orphan')
    incomes = db.relationship('Income', backref='user', lazy=True, cascade='all, delete-orphan')
    monthly_limits = db.relationship('MonthlyLimit', backref='user', lazy=True, cascade='all, delete-orphan')

class Expense(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    category = db.Column(db.String(50), nullable=False)
    amount = db.Column(db.Numeric(10, 2), nullable=False)
    description = db.Column(db.Text)
    date = db.Column(db.Date, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class Income(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    amount = db.Column(db.Numeric(10, 2), nullable=False)
    month = db.Column(db.Integer, nullable=False)  # 1-12
    year = db.Column(db.Integer, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class MonthlyLimit(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    limit_amount = db.Column(db.Numeric(10, 2), nullable=False)
    month = db.Column(db.Integer, nullable=False)  # 1-12
    year = db.Column(db.Integer, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

# Add a new model to track sent alerts
class BudgetAlert(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    month = db.Column(db.Integer, nullable=False)
    year = db.Column(db.Integer, nullable=False)
    sent_at = db.Column(db.DateTime, default=datetime.utcnow)
    amount_exceeded = db.Column(db.Numeric(10, 2), nullable=False)

# Helper functions
def send_budget_alert_email(user_email, user_name, current_spending, limit_amount):
    """Send email alert when budget limit is exceeded - ENHANCED VERSION"""
    try:
        print(f"DEBUG: === EMAIL SENDING ATTEMPT ===")
        print(f"DEBUG: Recipient: {user_email}")
        print(f"DEBUG: Current spending: ₹{current_spending}")
        print(f"DEBUG: Limit: ₹{limit_amount}")
        print(f"DEBUG: Mail server: {app.config['MAIL_SERVER']}")
        print(f"DEBUG: Mail port: {app.config['MAIL_PORT']}")
        print(f"DEBUG: Mail username: {app.config['MAIL_USERNAME']}")
        print(f"DEBUG: Mail password length: {len(app.config['MAIL_PASSWORD']) if app.config['MAIL_PASSWORD'] else 0}")
        
        # Create message
        msg = Message(
            subject='🚨 ExpenseTracker - Budget Alert!',
            recipients=[user_email],
            sender=app.config['MAIL_DEFAULT_SENDER']
        )
        
        # Enhanced HTML email template
        msg.html = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <meta charset="utf-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Budget Alert</title>
        </head>
        <body style="margin: 0; padding: 0; font-family: Arial, sans-serif; background-color: #f5f5f5;">
            <div style="max-width: 600px; margin: 0 auto; background-color: white; border-radius: 10px; overflow: hidden; box-shadow: 0 4px 6px rgba(0, 0, 0, 0.1);">
                <!-- Header -->
                <div style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); padding: 30px; text-align: center; color: white;">
                    <h1 style="margin: 0; font-size: 28px; font-weight: bold;">🚨 Budget Alert!</h1>
                    <p style="margin: 10px 0 0 0; font-size: 16px; opacity: 0.9;">ExpenseTracker Notification</p>
                </div>
                
                <!-- Content -->
                <div style="padding: 30px;">
                    <p style="font-size: 18px; color: #333; margin-bottom: 20px;">Hi {user_name},</p>
                    
                    <p style="font-size: 16px; color: #666; line-height: 1.6; margin-bottom: 25px;">
                        Your monthly spending has exceeded your set budget limit. Here's a quick summary:
                    </p>
                    
                    <!-- Summary Table -->
                    <div style="background: #f8f9fa; padding: 20px; border-radius: 8px; margin: 20px 0;">
                        <table style="width: 100%; border-collapse: collapse;">
                            <tr>
                                <td style="padding: 12px 0; border-bottom: 2px solid #e9ecef; font-weight: bold; color: #495057;">Current Spending:</td>
                                <td style="padding: 12px 0; border-bottom: 2px solid #e9ecef; text-align: right; color: #e74c3c; font-weight: bold; font-size: 18px;">₹{current_spending:.2f}</td>
                            </tr>
                            <tr>
                                <td style="padding: 12px 0; border-bottom: 2px solid #e9ecef; font-weight: bold; color: #495057;">Monthly Budget:</td>
                                <td style="padding: 12px 0; border-bottom: 2px solid #e9ecef; text-align: right; color: #3498db; font-weight: bold; font-size: 18px;">₹{limit_amount:.2f}</td>
                            </tr>
                            <tr>
                                <td style="padding: 12px 0; font-weight: bold; color: #495057;">Amount Exceeded:</td>
                                <td style="padding: 12px 0; text-align: right; color: #e74c3c; font-weight: bold; font-size: 20px;">₹{current_spending - limit_amount:.2f}</td>
                            </tr>
                        </table>
                    </div>
                    
                    <!-- Advice -->
                    <div style="background: #fff3cd; border: 1px solid #ffeaa7; border-radius: 8px; padding: 15px; margin: 20px 0;">
                        <p style="margin: 0; color: #856404; font-weight: 500;">
                            💡 <strong>Tip:</strong> Consider reviewing your recent expenses and adjusting your spending for the rest of the month.
                        </p>
                    </div>
                    
                    <p style="color: #666; font-size: 14px; margin-top: 30px; text-align: center;">
                        This is an automated alert from ExpenseTracker.<br>
                        Sent on {datetime.now().strftime('%B %d, %Y at %I:%M %p')}
                    </p>
                </div>
            </div>
        </body>
        </html>
        """
        
        # Also add plain text version
        msg.body = f"""
        Budget Alert - ExpenseTracker
        
        Hi {user_name},
        
        Your monthly spending has exceeded your budget limit:
        
        Current Spending: ₹{current_spending:.2f}
        Monthly Budget: ₹{limit_amount:.2f}
        Amount Exceeded: ₹{current_spending - limit_amount:.2f}
        
        Please review your expenses and adjust your spending accordingly.
        
        This is an automated alert from ExpenseTracker.
        """
        
        print(f"DEBUG: Attempting to send email...")
        mail.send(msg)
        print(f"DEBUG: ✅ Email sent successfully to {user_email}")
        return True
        
    except Exception as e:
        print(f"DEBUG: ❌ Failed to send email: {str(e)}")
        print(f"DEBUG: Error type: {type(e).__name__}")
        import traceback
        print(f"DEBUG: Full traceback: {traceback.format_exc()}")
        return False

def check_budget_limit(user_id):
    """Enhanced budget limit checker with better logging"""
    try:
        print(f"DEBUG: === BUDGET LIMIT CHECK ===")
        print(f"DEBUG: Checking budget for user_id: {user_id}")
        
        current_date = datetime.now()
        current_month = current_date.month
        current_year = current_date.year
        
        print(f"DEBUG: Current month/year: {current_month}/{current_year}")
        
        # Get current month's expenses
        monthly_expenses = db.session.query(db.func.sum(Expense.amount)).filter(
            Expense.user_id == user_id,
            db.extract('month', Expense.date) == current_month,
            db.extract('year', Expense.date) == current_year
        ).scalar() or 0
        
        print(f"DEBUG: Total monthly expenses: ₹{monthly_expenses}")
        
        # Get monthly limit
        monthly_limit = MonthlyLimit.query.filter_by(
            user_id=user_id,
            month=current_month,
            year=current_year
        ).first()
        
        if not monthly_limit:
            print(f"DEBUG: No monthly limit set for user {user_id}")
            return False
            
        print(f"DEBUG: Monthly limit: ₹{monthly_limit.limit_amount}")
        print(f"DEBUG: Budget exceeded: {monthly_expenses > monthly_limit.limit_amount}")
        
        if monthly_expenses > monthly_limit.limit_amount:
            print(f"DEBUG: Budget exceeded! Checking if alert already sent...")
            
            # Check if we already sent an alert for this month
            existing_alert = BudgetAlert.query.filter_by(
                user_id=user_id,
                month=current_month,
                year=current_year
            ).first()
            
            if existing_alert:
                print(f"DEBUG: Alert already sent this month on {existing_alert.sent_at}")
                return False
            
            # Get user details
            user = User.query.get(user_id)
            if not user:
                print(f"DEBUG: User {user_id} not found")
                return False
                
            print(f"DEBUG: Sending email to {user.email}")
            
            # Send email
            email_sent = send_budget_alert_email(
                user.email,
                user.name,
                float(monthly_expenses),
                float(monthly_limit.limit_amount)
            )
            
            if email_sent:
                # Record that we sent the alert
                alert_record = BudgetAlert(
                    user_id=user_id,
                    month=current_month,
                    year=current_year,
                    amount_exceeded=monthly_expenses - monthly_limit.limit_amount
                )
                db.session.add(alert_record)
                db.session.commit()
                print(f"DEBUG: Alert record saved to database")
                return True
            else:
                print(f"DEBUG: Failed to send email")
                return False
        
        print(f"DEBUG: Budget not exceeded, no alert needed")
        return False
        
    except Exception as e:
        print(f"DEBUG: Error in check_budget_limit: {str(e)}")
        import traceback
        print(f"DEBUG: Full traceback: {traceback.format_exc()}")
        return False

def check_and_reset_monthly_data(user_id):
    """Check if it's a new month and reset data if needed"""
    try:
        current_date = datetime.now()
        current_month = current_date.month
        current_year = current_date.year
        
        # Check if user has any expenses this month
        existing_expenses = Expense.query.filter(
            Expense.user_id == user_id,
            db.extract('month', Expense.date) == current_month,
            db.extract('year', Expense.date) == current_year
        ).first()
        
        # If no expenses this month, it might be a new month
        if not existing_expenses:
            # Check if user had expenses last month
            last_month = current_month - 1 if current_month > 1 else 12
            last_year = current_year if current_month > 1 else current_year - 1
            
            last_month_expenses = Expense.query.filter(
                Expense.user_id == user_id,
                db.extract('month', Expense.date) == last_month,
                db.extract('year', Expense.date) == last_year
            ).first()
            
            if last_month_expenses:
                print(f"DEBUG: New month detected for user {user_id}, data reset automatically")
                return True
        
        return False
        
    except Exception as e:
        print(f"DEBUG: Error in monthly reset check: {str(e)}")
        return False

# Test email endpoint (for debugging)
@app.route('/api/test-email', methods=['POST'])
@jwt_required()
def test_email():
    """Test endpoint to check email functionality"""
    try:
        user_id = int(get_jwt_identity())
        user = User.query.get(user_id)
        
        if not user:
            return jsonify({'message': 'User not found'}), 404
        
        print(f"DEBUG: Testing email for user: {user.email}")
        
        # Send test email
        result = send_budget_alert_email(
            user.email,
            user.name,
            1500.00,  # Test amount
            1000.00   # Test limit
        )
        
        if result:
            return jsonify({'message': 'Test email sent successfully!'}), 200
        else:
            return jsonify({'message': 'Failed to send test email'}), 500
            
    except Exception as e:
        print(f"DEBUG: Error in test_email: {str(e)}")
        return jsonify({'message': 'Test email failed', 'error': str(e)}), 500

# Routes (keeping all existing routes and adding enhanced logging)
@app.route('/api/auth/register', methods=['POST'])
def register():
    try:
        data = request.get_json()
        print(f"DEBUG: Registration attempt for: {data.get('email')}")
        
        if not data.get('name') or not data.get('email') or not data.get('password'):
            return jsonify({'message': 'Name, email, and password are required'}), 400
        
        if User.query.filter_by(email=data['email']).first():
            return jsonify({'message': 'Email already registered'}), 400
        
        password_hash = bcrypt.generate_password_hash(data['password']).decode('utf-8')
        
        user = User(
            name=data['name'],
            email=data['email'],
            password_hash=password_hash
        )
        
        db.session.add(user)
        db.session.commit()
        
        print(f"DEBUG: User created successfully: {user.id}")
        return jsonify({'message': 'User created successfully'}), 201
        
    except Exception as e:
        print(f"DEBUG: Registration error: {str(e)}")
        return jsonify({'message': 'Registration failed', 'error': str(e)}), 500

@app.route('/api/auth/login', methods=['POST'])
def login():
    try:
        data = request.get_json()
        print(f"DEBUG: Login attempt for: {data.get('email')}")
        
        if not data.get('email') or not data.get('password'):
            return jsonify({'message': 'Email and password are required'}), 400
        
        user = User.query.filter_by(email=data['email']).first()
        
        if user and bcrypt.check_password_hash(user.password_hash, data['password']):
            access_token = create_access_token(identity=str(user.id))
            print(f"DEBUG: Login successful for user: {user.id}")
            
            return jsonify({
                'token': access_token,
                'user': {
                    'id': user.id,
                    'name': user.name,
                    'email': user.email
                }
            }), 200
        
        print(f"DEBUG: Login failed for: {data.get('email')}")
        return jsonify({'message': 'Invalid credentials'}), 401
        
    except Exception as e:
        print(f"DEBUG: Login error: {str(e)}")
        return jsonify({'message': 'Login failed', 'error': str(e)}), 500

@app.route('/api/expenses', methods=['GET'])
@jwt_required()
def get_expenses():
    try:
        user_id = int(get_jwt_identity())
        
        # Check for monthly reset
        check_and_reset_monthly_data(user_id)
        
        current_date = datetime.now()
        current_month = current_date.month
        current_year = current_date.year
        
        expenses = Expense.query.filter(
            Expense.user_id == user_id,
            db.extract('month', Expense.date) == current_month,
            db.extract('year', Expense.date) == current_year
        ).order_by(Expense.created_at.desc()).all()
        
        expenses_data = []
        for expense in expenses:
            expenses_data.append({
                'id': expense.id,
                'category': expense.category,
                'amount': float(expense.amount),
                'description': expense.description,
                'date': expense.date.strftime('%Y-%m-%d'),
                'created_at': expense.created_at.strftime('%Y-%m-%d %H:%M')
            })
        
        return jsonify(expenses_data), 200
        
    except Exception as e:
        print(f"DEBUG: Error in get_expenses: {str(e)}")
        return jsonify({'message': 'Failed to fetch expenses', 'error': str(e)}), 500

@app.route('/api/expenses', methods=['POST'])
@jwt_required()
def add_expense():
    try:
        user_id = int(get_jwt_identity())
        data = request.get_json()
        
        print(f"DEBUG: Adding expense for user {user_id}: {data}")
        
        if not data.get('category') or not data.get('amount'):
            return jsonify({'message': 'Category and amount are required'}), 400
        
        try:
            amount = float(data['amount'])
            if amount <= 0:
                return jsonify({'message': 'Amount must be greater than 0'}), 400
        except (ValueError, TypeError):
            return jsonify({'message': 'Invalid amount format'}), 400
        
        try:
            expense_date = datetime.strptime(data['date'], '%Y-%m-%d').date()
        except (ValueError, TypeError):
            return jsonify({'message': 'Invalid date format'}), 400
        
        expense = Expense(
            user_id=user_id,
            category=data['category'],
            amount=amount,
            description=data.get('description', ''),
            date=expense_date
        )
        
        db.session.add(expense)
        db.session.commit()
        
        print(f"DEBUG: Expense added successfully, checking budget limit...")
        
        # Check budget limit after adding expense
        budget_exceeded = check_budget_limit(user_id)
        
        response_data = {'message': 'Expense added successfully'}
        if budget_exceeded:
            response_data['budget_alert'] = 'Budget limit exceeded! Email alert sent.'
        
        return jsonify(response_data), 201
        
    except Exception as e:
        print(f"DEBUG: Error in add_expense: {str(e)}")
        db.session.rollback()
        return jsonify({'message': 'Failed to add expense', 'error': str(e)}), 500

@app.route('/api/expenses/<int:expense_id>', methods=['DELETE'])
@jwt_required()
def delete_expense(expense_id):
    try:
        user_id = int(get_jwt_identity())
        
        # Find the expense and verify it belongs to the user
        expense = Expense.query.filter_by(id=expense_id, user_id=user_id).first()
        
        if not expense:
            return jsonify({'message': 'Expense not found'}), 404
        
        db.session.delete(expense)
        db.session.commit()
        
        print(f"DEBUG: Expense {expense_id} deleted successfully")
        return jsonify({'message': 'Expense deleted successfully'}), 200
        
    except Exception as e:
        print(f"DEBUG: Error in delete_expense: {str(e)}")
        db.session.rollback()
        return jsonify({'message': 'Failed to delete expense', 'error': str(e)}), 500

@app.route('/api/income', methods=['GET'])
@jwt_required()
def get_income():
    try:
        user_id = int(get_jwt_identity())
        current_date = datetime.now()
        current_month = current_date.month
        current_year = current_date.year
        
        income = Income.query.filter_by(
            user_id=user_id, 
            month=current_month, 
            year=current_year
        ).first()
        
        if income:
            return jsonify({
                'id': income.id,
                'amount': float(income.amount),
                'month': income.month,
                'year': income.year
            }), 200
        
        return jsonify({'message': 'No income set for current month'}), 404
        
    except Exception as e:
        print(f"DEBUG: Error in get_income: {str(e)}")
        return jsonify({'message': 'Failed to fetch income', 'error': str(e)}), 500

@app.route('/api/income', methods=['POST'])
@jwt_required()
def set_income():
    try:
        user_id = int(get_jwt_identity())
        data = request.get_json()
        
        if not data.get('amount'):
            return jsonify({'message': 'Amount is required'}), 400
        
        current_date = datetime.now()
        current_month = current_date.month
        current_year = current_date.year
        
        existing_income = Income.query.filter_by(
            user_id=user_id, 
            month=current_month, 
            year=current_year
        ).first()
        
        if existing_income:
            existing_income.amount = data['amount']
        else:
            income = Income(
                user_id=user_id,
                amount=data['amount'],
                month=current_month,
                year=current_year
            )
            db.session.add(income)
        
        db.session.commit()
        return jsonify({'message': 'Income updated successfully'}), 200
        
    except Exception as e:
        print(f"DEBUG: Error in set_income: {str(e)}")
        return jsonify({'message': 'Failed to update income', 'error': str(e)}), 500

@app.route('/api/monthly-limit', methods=['GET'])
@jwt_required()
def get_monthly_limit():
    try:
        user_id = int(get_jwt_identity())
        current_date = datetime.now()
        current_month = current_date.month
        current_year = current_date.year
        
        monthly_limit = MonthlyLimit.query.filter_by(
            user_id=user_id, 
            month=current_month, 
            year=current_year
        ).first()
        
        if monthly_limit:
            return jsonify({
                'limit': float(monthly_limit.limit_amount),
                'month': monthly_limit.month,
                'year': monthly_limit.year
            }), 200
        
        return jsonify({'limit': 0}), 200
        
    except Exception as e:
        print(f"DEBUG: Error in get_monthly_limit: {str(e)}")
        return jsonify({'message': 'Failed to fetch monthly limit', 'error': str(e)}), 500

@app.route('/api/monthly-limit', methods=['POST'])
@jwt_required()
def set_monthly_limit():
    try:
        user_id = int(get_jwt_identity())
        data = request.get_json()
        
        if not data.get('limit'):
            return jsonify({'message': 'Limit amount is required'}), 400
        
        current_date = datetime.now()
        current_month = current_date.month
        current_year = current_date.year
        
        existing_limit = MonthlyLimit.query.filter_by(
            user_id=user_id, 
            month=current_month, 
            year=current_year
        ).first()
        
        if existing_limit:
            existing_limit.limit_amount = data['limit']
        else:
            monthly_limit = MonthlyLimit(
                user_id=user_id,
                limit_amount=data['limit'],
                month=current_month,
                year=current_year
            )
            db.session.add(monthly_limit)
        
        db.session.commit()
        
        # Clear any existing alert records for this month so user can get new alerts
        BudgetAlert.query.filter_by(
            user_id=user_id,
            month=current_month,
            year=current_year
        ).delete()
        db.session.commit()
        
        return jsonify({'message': 'Monthly limit updated successfully'}), 200
        
    except Exception as e:
        print(f"DEBUG: Error in set_monthly_limit: {str(e)}")
        return jsonify({'message': 'Failed to update monthly limit', 'error': str(e)}), 500

@app.route('/api/health', methods=['GET'])
def health_check():
    try:
        db.session.execute(db.text('SELECT 1'))
        return jsonify({
            'status': 'healthy',
            'database': 'connected',
            'timestamp': datetime.now().isoformat(),
            'environment': os.getenv('FLASK_ENV', 'production'),
            'email_configured': bool(app.config['MAIL_USERNAME'] and app.config['MAIL_PASSWORD'])
        }), 200
    except Exception as e:
        return jsonify({
            'status': 'unhealthy',
            'database': 'disconnected',
            'error': str(e),
            'timestamp': datetime.now().isoformat()
        }), 500

@app.route('/api/auth/validate', methods=['GET'])
@jwt_required()
def validate_token():
    try:
        user_id = int(get_jwt_identity())
        user = User.query.get(user_id)
        
        if user:
            return jsonify({
                'valid': True,
                'user': {
                    'id': user.id,
                    'name': user.name,
                    'email': user.email
                }
            }), 200
        
        return jsonify({'valid': False, 'message': 'User not found'}), 404
        
    except Exception as e:
        return jsonify({'valid': False, 'message': str(e)}), 401

# Create tables
with app.app_context():
    try:
        db.create_all()
        print("DEBUG: Database tables created successfully")
    except Exception as e:
        print(f"DEBUG: Error creating tables: {str(e)}")

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    debug_mode = os.getenv('FLASK_ENV') == 'development'
    print(f"DEBUG: Starting Flask server on port {port}...")
    print(f"DEBUG: Debug mode: {debug_mode}")
    app.run(debug=debug_mode, port=port, host='0.0.0.0')
