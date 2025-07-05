from flask import Flask, request, session, redirect, url_for, render_template, flash, jsonify
import boto3
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import logging
import os
import uuid
from dotenv import load_dotenv
from boto3.dynamodb.conditions import Attr

# Load environment variables
load_dotenv()

# ---------------------------------------
# Flask App Initialization
# ---------------------------------------
app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'fleetsync_secret_key_2024')

# ---------------------------------------
# App Configuration
# ---------------------------------------
AWS_REGION_NAME = os.environ.get('AWS_REGION_NAME', 'us-east-1')

# Email Configuration
SMTP_SERVER = os.environ.get('SMTP_SERVER', 'smtp.gmail.com')
SMTP_PORT = int(os.environ.get('SMTP_PORT', 587))
SENDER_EMAIL = os.environ.get('SENDER_EMAIL')
SENDER_PASSWORD = os.environ.get('SENDER_PASSWORD')
ENABLE_EMAIL = os.environ.get('ENABLE_EMAIL', 'False').lower() == 'true'

# Table Names from .env
USERS_TABLE_NAME = os.environ.get('USERS_TABLE_NAME', 'FleetSyncUsers')
VEHICLES_TABLE_NAME = os.environ.get('VEHICLES_TABLE_NAME', 'FleetSyncVehicles')
MAINTENANCE_TABLE_NAME = os.environ.get('MAINTENANCE_TABLE_NAME', 'FleetSyncMaintenance')
TRIPS_TABLE_NAME = os.environ.get('TRIPS_TABLE_NAME', 'FleetSyncTrips')

# SNS Configuration
SNS_TOPIC_ARN = os.environ.get('SNS_TOPIC_ARN')
ENABLE_SNS = os.environ.get('ENABLE_SNS', 'False').lower() == 'true'

# ---------------------------------------
# AWS Resources
# ---------------------------------------
dynamodb = boto3.resource('dynamodb', region_name=AWS_REGION_NAME)
sns = boto3.client('sns', region_name=AWS_REGION_NAME)

# DynamoDB Tables
users_table = dynamodb.Table(USERS_TABLE_NAME)
vehicles_table = dynamodb.Table(VEHICLES_TABLE_NAME)
maintenance_table = dynamodb.Table(MAINTENANCE_TABLE_NAME)
trips_table = dynamodb.Table(TRIPS_TABLE_NAME)

# ---------------------------------------
# Logging
# ---------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler("fleetsync.log"),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# ---------------------------------------
# Helper Functions
# ---------------------------------------
def is_logged_in():
    return 'email' in session

def get_user_role(email):
    try:
        response = users_table.get_item(Key={'email': email})
        return response.get('Item', {}).get('role')
    except Exception as e:
        logger.error(f"Error fetching role: {e}")
    return None

def send_email(to_email, subject, body):
    if not ENABLE_EMAIL:
        logger.info(f"[Email Skipped] Subject: {subject} to {to_email}")
        return

    try:
        msg = MIMEMultipart()
        msg['From'] = SENDER_EMAIL
        msg['To'] = to_email
        msg['Subject'] = subject
        msg.attach(MIMEText(body, 'plain'))

        server = smtplib.SMTP(SMTP_SERVER, SMTP_PORT)
        server.starttls()
        server.login(SENDER_EMAIL, SENDER_PASSWORD)
        server.sendmail(SENDER_EMAIL, to_email, msg.as_string())
        server.quit()

        logger.info(f"Email sent to {to_email}")
    except Exception as e:
        logger.error(f"Email sending failed: {e}")

def publish_to_sns(message, subject="FleetSync Notification"):
    if not ENABLE_SNS:
        logger.info("[SNS Skipped] Message: {}".format(message))
        return

    try:
        response = sns.publish(
            TopicArn=SNS_TOPIC_ARN,
            Message=message,
            Subject=subject
        )
        logger.info(f"SNS published: {response['MessageId']}")
    except Exception as e:
        logger.error(f"SNS publish failed: {e}")

def require_role(required_role):
    def decorator(f):
        def decorated_function(*args, **kwargs):
            if not is_logged_in():
                flash('Please log in to access this page', 'warning')
                return redirect(url_for('login'))
            
            user_role = session.get('role')
            if user_role != required_role and required_role != 'any':
                flash('Access denied. Insufficient permissions.', 'danger')
                return redirect(url_for('dashboard'))
            
            return f(*args, **kwargs)
        decorated_function.__name__ = f.__name__
        return decorated_function
    return decorator

# ---------------------------------------
# Routes
# ---------------------------------------

# Home Page
@app.route('/')
def index():
    if is_logged_in():
        return redirect(url_for('dashboard'))
    return render_template('index.html')

# Register User (Fleet Manager/Driver/Admin)
@app.route('/register', methods=['GET', 'POST'])
def register():
    if is_logged_in():
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        # Form validation
        required_fields = ['name', 'email', 'password', 'role']
        for field in required_fields:
            if field not in request.form or not request.form[field]:
                flash(f'Please fill in the {field} field', 'danger')
                return render_template('register.html')
        
        # Check if passwords match
        if request.form['password'] != request.form.get('confirm_password', ''):
            flash('Passwords do not match', 'danger')
            return render_template('register.html')
        
        name = request.form['name']
        email = request.form['email']
        password = generate_password_hash(request.form['password'])
        role = request.form['role']  # 'fleet_manager', 'driver', 'admin'
        phone = request.form.get('phone', '')
        license_number = request.form.get('license_number', '')
        
        # Check if user already exists
        existing_user = users_table.get_item(Key={'email': email}).get('Item')
        if existing_user:
            flash('Email already registered', 'danger')
            return render_template('register.html')

        # Add user to DynamoDB
        user_item = {
            'email': email,
            'name': name,
            'password': password,
            'role': role,
            'phone': phone,
            'login_count': 0,
            'status': 'active',
            'created_at': datetime.now().isoformat(),
        }
        
        # Add license number for drivers
        if role == 'driver' and license_number:
            user_item['license_number'] = license_number
        
        users_table.put_item(Item=user_item)
        
        # Send welcome email
        welcome_msg = f"Welcome to FleetSync, {name}! Your {role} account has been created successfully."
        send_email(email, "Welcome to FleetSync", welcome_msg)
        
        # Send admin notification
        publish_to_sns(f'New {role} registered: {name} ({email})', 'New User Registration')
        
        flash('Registration successful. Please log in.', 'success')
        return redirect(url_for('login'))
    
    return render_template('register.html')

# Login User
@app.route('/login', methods=['GET', 'POST'])
def login():
    if is_logged_in():
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        
        if not email or not password:
            flash('Email and password are required', 'danger')
            return render_template('login.html')

        # Validate user credentials
        user = users_table.get_item(Key={'email': email}).get('Item')

        if user and check_password_hash(user['password'], password):
            if user.get('status') != 'active':
                flash('Account is inactive. Contact administrator.', 'warning')
                return render_template('login.html')
                
            session['email'] = email
            session['role'] = user['role']
            session['name'] = user.get('name', '')
            
            # Update login count
            try:
                users_table.update_item(
                    Key={'email': email},
                    UpdateExpression='SET login_count = if_not_exists(login_count, :zero) + :inc, last_login = :now',
                    ExpressionAttributeValues={
                        ':inc': 1, 
                        ':zero': 0, 
                        ':now': datetime.now().isoformat()
                    }
                )
            except Exception as e:
                logger.error(f"Failed to update login info: {e}")
            
            flash(f'Welcome back, {user.get("name", "")}!', 'success')
            return redirect(url_for('dashboard'))
        else:
            flash('Invalid email or password.', 'danger')

    return render_template('login.html')

# Dashboard
@app.route('/dashboard')
@require_role('any')
def dashboard():
    user_role = session.get('role')
    email = session.get('email')
    
    dashboard_data = {
        'role': user_role,
        'name': session.get('name'),
        'email': email
    }
    
    try:
        if user_role == 'fleet_manager':
            # Get vehicle count and recent activities
            vehicles_response = vehicles_table.scan()
            vehicles_items = vehicles_response.get('Items', [])
            dashboard_data['total_vehicles'] = len(vehicles_items)
            dashboard_data['active_vehicles'] = len([v for v in vehicles_items if v.get('status') == 'active'])
            
        elif user_role == 'driver':
            # Get assigned vehicles and recent trips
            vehicles_response = vehicles_table.scan(
                FilterExpression=Attr('assigned_driver').eq(email)
            )
            dashboard_data['assigned_vehicles'] = vehicles_response.get('Items', [])
            
        elif user_role == 'admin':
            # Get system overview
            users_response = users_table.scan()
            vehicles_response = vehicles_table.scan()
            dashboard_data['total_users'] = len(users_response.get('Items', []))
            dashboard_data['total_vehicles'] = len(vehicles_response.get('Items', []))
            
    except Exception as e:
        logger.error(f"Dashboard data fetch error: {e}")
        flash('Error loading dashboard data', 'warning')
    
    return render_template('dashboard.html', data=dashboard_data)

# Vehicle Management Routes
@app.route('/vehicles')
@require_role('any')
def vehicles():
    try:
        if session.get('role') == 'driver':
            # Drivers see only assigned vehicles
            response = vehicles_table.scan(
                FilterExpression=Attr('assigned_driver').eq(session.get('email'))
            )
        else:
            # Fleet managers and admins see all vehicles
            response = vehicles_table.scan()
        
        vehicles_list = response.get('Items', [])
        logger.info(f"Vehicles fetched successfully: {len(vehicles_list)} vehicles")
        return render_template('vehicles.html', vehicles=vehicles_list)
    except Exception as e:
        logger.error(f"Error fetching vehicles: {str(e)}")
        flash('Error loading vehicles', 'danger')
        return redirect(url_for('dashboard'))

@app.route('/add_vehicle', methods=['GET', 'POST'])
@require_role('fleet_manager')
def add_vehicle():
    if request.method == 'POST':
        required_fields = ['vehicle_id', 'make', 'model', 'year', 'license_plate']
        for field in required_fields:
            if not request.form.get(field):
                flash(f'Please fill in the {field} field', 'danger')
                return render_template('add_vehicle.html')
        
        vehicle_id = request.form['vehicle_id']
        
        # Check if vehicle already exists
        existing_vehicle = vehicles_table.get_item(Key={'vehicle_id': vehicle_id}).get('Item')
        if existing_vehicle:
            flash('Vehicle ID already exists', 'danger')
            return render_template('add_vehicle.html')
        
        vehicle_item = {
            'vehicle_id': vehicle_id,
            'make': request.form['make'],
            'model': request.form['model'],
            'year': int(request.form['year']),
            'license_plate': request.form['license_plate'],
            'status': 'active',
            'mileage': int(request.form.get('mileage', 0)),
            'fuel_type': request.form.get('fuel_type', 'gasoline'),
            'assigned_driver': request.form.get('assigned_driver', ''),
            'created_by': session.get('email'),
            'created_at': datetime.now().isoformat(),
        }
        
        vehicles_table.put_item(Item=vehicle_item)
        
        # Send notification
        publish_to_sns(f'New vehicle added: {vehicle_item["make"]} {vehicle_item["model"]} ({vehicle_id})', 'Vehicle Added')
        
        flash('Vehicle added successfully', 'success')
        return redirect(url_for('vehicles'))
    
    return render_template('add_vehicle.html')

# Maintenance Management Routes
@app.route('/maintenance')
@require_role('any')
def maintenance():
    try:
        response = maintenance_table.scan()
        maintenance_list = response.get('Items', [])
        
        # Sort by scheduled date
        maintenance_list.sort(key=lambda x: x.get('scheduled_date', ''), reverse=True)
        
        logger.info(f"Maintenance records fetched successfully: {len(maintenance_list)} records")
        return render_template('maintenance.html', maintenance_records=maintenance_list)
    except Exception as e:
        logger.error(f"Error fetching maintenance records: {str(e)}")
        flash('Error loading maintenance records', 'danger')
        return redirect(url_for('dashboard'))

@app.route('/schedule_maintenance', methods=['GET', 'POST'])
@require_role('fleet_manager')
def schedule_maintenance():
    if request.method == 'POST':
        required_fields = ['vehicle_id', 'maintenance_type', 'scheduled_date']
        for field in required_fields:
            if not request.form.get(field):
                flash(f'Please fill in the {field} field', 'danger')
                return render_template('schedule_maintenance.html')
        
        maintenance_id = str(uuid.uuid4())
        vehicle_id = request.form['vehicle_id']
        maintenance_type = request.form['maintenance_type']
        scheduled_date = request.form['scheduled_date']
        
        maintenance_item = {
            'maintenance_id': maintenance_id,
            'vehicle_id': vehicle_id,
            'maintenance_type': maintenance_type,
            'scheduled_date': scheduled_date,
            'status': 'scheduled',
            'description': request.form.get('description', ''),
            'estimated_cost': float(request.form.get('estimated_cost', 0)),
            'scheduled_by': session.get('email'),
            'created_at': datetime.now().isoformat(),
        }
        
        maintenance_table.put_item(Item=maintenance_item)
        
        # Send notification
        publish_to_sns(
            f'Maintenance scheduled for vehicle {vehicle_id}: {maintenance_type} on {scheduled_date}',
            'Maintenance Scheduled'
        )
        
        flash('Maintenance scheduled successfully', 'success')
        return redirect(url_for('maintenance'))
    
    # Get vehicles for dropdown
    try:
        vehicles_response = vehicles_table.scan()
        vehicles_list = vehicles_response.get('Items', [])
    except Exception as e:
        logger.error(f"Error fetching vehicles for dropdown: {e}")
        vehicles_list = []
    
    return render_template('schedule_maintenance.html', vehicles=vehicles_list)

# Trip Management Routes
@app.route('/trips')
@require_role('any')
def trips():
    try:
        if session.get('role') == 'driver':
            # Drivers see only their trips
            response = trips_table.scan(
                FilterExpression=Attr('driver_email').eq(session.get('email'))
            )
        else:
            # Fleet managers and admins see all trips
            response = trips_table.scan()
        
        trips_list = response.get('Items', [])
        trips_list.sort(key=lambda x: x.get('start_time', ''), reverse=True)
        
        logger.info(f"Trips fetched successfully: {len(trips_list)} trips")
        return render_template('trips.html', trips=trips_list)
    except Exception as e:
        logger.error(f"Error fetching trips: {str(e)}")
        flash('Error loading trips', 'danger')
        return redirect(url_for('dashboard'))


@app.route('/log_trip', methods=['GET', 'POST'])
@require_role('driver')
def log_trip():
    # TEST fallback session (remove in production)
    if 'email' not in session:
        session['email'] = 'john@example.com'  # test email
    if 'name' not in session:
        session['name'] = 'John Doe'

    if request.method == 'POST':
        required_fields = ['vehicle_id', 'start_location', 'end_location', 'start_mileage', 'end_mileage']
        for field in required_fields:
            if not request.form.get(field):
                flash(f'Please fill in the {field} field', 'danger')
                # Get vehicles again for the form
                try:
                    vehicles_response = vehicles_table.scan(
                        FilterExpression=Attr('assigned_driver').eq(session.get('email'))
                    )
                    vehicles_list = vehicles_response.get('Items', [])
                except Exception as e:
                    logger.error(f"Error fetching vehicles for form reload: {e}")
                    vehicles_list = []
                return render_template('log_trip.html', vehicles=vehicles_list)
        
        trip_id = str(uuid.uuid4())
        
        trip_item = {
            'trip_id': trip_id,
            'vehicle_id': request.form['vehicle_id'],
            'driver_email': session.get('email'),
            'driver_name': session.get('name'),
            'start_location': request.form['start_location'],
            'end_location': request.form['end_location'],
            'start_mileage': int(request.form['start_mileage']),
            'end_mileage': int(request.form['end_mileage']),
            'distance': int(request.form['end_mileage']) - int(request.form['start_mileage']),
            'fuel_used': float(request.form.get('fuel_used', 0)),
            'purpose': request.form.get('purpose', ''),
            'notes': request.form.get('notes', ''),
            'start_time': datetime.now().isoformat(),
            'status': 'completed'
        }
        
        trips_table.put_item(Item=trip_item)
        
        # Update vehicle mileage
        try:
            vehicles_table.update_item(
                Key={'vehicle_id': request.form['vehicle_id']},
                UpdateExpression='SET mileage = :mileage',
                ExpressionAttributeValues={':mileage': int(request.form['end_mileage'])}
            )
        except Exception as e:
            logger.error(f"Failed to update vehicle mileage: {e}")
        
        flash('Trip logged successfully', 'success')
        return redirect(url_for('trips'))
    
    # Get assigned vehicles for driver
    try:
        vehicles_response = vehicles_table.scan(
            FilterExpression=Attr('assigned_driver').eq(session.get('email'))
        )
        vehicles_list = vehicles_response.get('Items', [])
        logger.info(f"Fetched vehicles for {session.get('email')}: {len(vehicles_list)} vehicles")
    except Exception as e:
        logger.error(f"Error fetching vehicles: {str(e)}")
        vehicles_list = []
    
    return render_template('log_trip.html', vehicles=vehicles_list)

# Admin Routes
@app.route('/admin/users')
@require_role('admin')
def admin_users():
    try:
        response = users_table.scan()
        users_list = response.get('Items', [])
        logger.info(f"Admin users fetched successfully: {len(users_list)} users")
        return render_template('admin_users.html', users=users_list)
    except Exception as e:
        logger.error(f"Error fetching users: {str(e)}")
        flash('Error loading users', 'danger')
        return redirect(url_for('dashboard'))

# API Routes for mobile/AJAX
@app.route('/api/vehicle_status/<vehicle_id>')
@require_role('any')
def api_vehicle_status(vehicle_id):
    try:
        vehicle = vehicles_table.get_item(Key={'vehicle_id': vehicle_id}).get('Item')
        if vehicle:
            return jsonify({
                'status': 'success',
                'data': {
                    'vehicle_id': vehicle['vehicle_id'],
                    'status': vehicle.get('status', 'unknown'),
                    'mileage': vehicle.get('mileage', 0),
                    'assigned_driver': vehicle.get('assigned_driver', '')
                }
            })
        else:
            return jsonify({'status': 'error', 'message': 'Vehicle not found'}), 404
    except Exception as e:
        logger.error(f"API error: {str(e)}")
        return jsonify({'status': 'error', 'message': 'Internal server error'}), 500

# Logout
@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out successfully.', 'info')
    return redirect(url_for('index'))

# Error handlers
@app.errorhandler(404)
def not_found_error(error):
    return render_template('404.html'), 404

@app.errorhandler(500)
def internal_error(error):
    return render_template('500.html'), 500

# Run the application
if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
