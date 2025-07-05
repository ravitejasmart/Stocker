from flask import Flask, render_template, request, redirect, url_for, flash, session
import boto3
import os
import uuid
from datetime import datetime
from boto3.dynamodb.conditions import Key, Attr
from decimal import Decimal
import json

app = Flask(__name__)
app.secret_key = "stocker_secret_2024"

# AWS Configuration
# For local development - use environment variables
# For EC2 deployment with IAM role - remove credentials and just use region
AWS_ACCESS_KEY = os.environ.get('AWS_ACCESS_KEY_ID')
AWS_SECRET_KEY = os.environ.get('AWS_SECRET_ACCESS_KEY')
AWS_REGION = os.environ.get('AWS_REGION', 'us-east-1')

# Set up boto3 session
if AWS_ACCESS_KEY and AWS_SECRET_KEY:
    # Local development with explicit credentials
    boto3_session = boto3.Session(
        aws_access_key_id=AWS_ACCESS_KEY,
        aws_secret_access_key=AWS_SECRET_KEY,
        region_name=AWS_REGION
    )
else:
    # EC2 instance with IAM role
    boto3_session = boto3.Session(region_name=AWS_REGION)

# Create DynamoDB resource
dynamodb = boto3_session.resource('dynamodb')

# Define table names
USER_TABLE = 'stocker_users'
STOCK_TABLE = 'stocker_stocks'
TRANSACTION_TABLE = 'stocker_transactions'
PORTFOLIO_TABLE = 'stocker_portfolio'

# Helper class for DynamoDB item serialization
class DecimalEncoder(json.JSONEncoder):
    def default(self, o):
        if isinstance(o, Decimal):
            return float(o)
        return super(DecimalEncoder, self).default(o)

# Helper function to convert DynamoDB response to Python dict
def clean_dynamo_response(response):
    if not response:
        return None
    return json.loads(json.dumps(response, cls=DecimalEncoder))

# Create SNS client
if AWS_ACCESS_KEY and AWS_SECRET_KEY:
    sns = boto3_session.client('sns')
else:
    sns = boto3.client('sns', region_name=AWS_REGION)

# SNS Topic ARNs
USER_ACCOUNT_TOPIC_ARN = "arn:aws:sns:us-east-1:604665149129:StockerUserAccountTopic"
TRANSACTION_TOPIC_ARN = "arn:aws:sns:us-east-1:604665149129:StockerTransactionTopic"

def send_notification(topic_arn, subject, message, attributes=None):
    """Send an SNS notification"""
    if not topic_arn:
        print(f"Warning: Missing SNS topic ARN for notification: {subject}")
        return False

    try:
        kwargs = {
            'TopicArn': topic_arn,
            'Subject': subject,
            'Message': message
        }

        if attributes:
            kwargs['MessageAttributes'] = attributes
        response = sns.publish(**kwargs)
        return True
    except Exception as e:
        print(f"SNS notification failed: {str(e)}")
        return False
# ------------------- Data Access Functions ------------------- #
def get_user_by_email(email):
    """Get user by email"""
    table = dynamodb.Table(USER_TABLE)
    response = table.get_item(Key={'email': email})
    return response.get('Item')

def create_user(username, email, password, role):
    """Create a new user"""
    table = dynamodb.Table(USER_TABLE)
    user = {
        'id': str(uuid.uuid4()),
        'username': username,
        'email': email,
        'password': password,
        'role': role
    }
    table.put_item(Item=user)
    return user

def get_all_stocks():
    """Get all stocks"""
    table = dynamodb.Table(STOCK_TABLE)
    response = table.scan()
    return response.get('Items', [])

def get_stock_by_id(stock_id):
    """Get stock by ID"""
    table = dynamodb.Table(STOCK_TABLE)
    response = table.get_item(Key={'id': stock_id})
    return response.get('Item')

def get_traders():
    """Get all traders"""
    table = dynamodb.Table(USER_TABLE)
    response = table.scan(
        FilterExpression=Attr('role').eq('trader')
    )
    return response.get('Items', [])

def delete_trader_by_id(trader_id):
    """Delete a trader by ID"""
    # First, get the user's email
    user = get_user_by_id(trader_id)
    if not user:
        print(f"User with ID {trader_id} not found")
        return False

    email = user.get('email')
    if not email:
        print(f"User with ID {trader_id} has no email")
        return False

    # 1. Delete the user
    user_table = dynamodb.Table(USER_TABLE)
    user_table.delete_item(Key={'email': trader_id})
    for item in portfolio_response.get('Items', []):
        portfolio_table.delete_item(
            Key={
                'user_id': trader_id,
                'stock_id': item['stock_id']
            }
        )
    # 2. Delete all portfolio items for the user
    portfolio_table = dynamodb.Table(PORTFOLIO_TABLE)
    portfolio_response = portfolio_table.query(
        KeyConditionExpression=Key('user_id').eq(trader_id)
    )

    # 3. We might want to keep transactions for audit purposes
    return True

def get_transactions():
    """Get all transactions with user and stock details"""
    table = dynamodb.Table(TRANSACTION_TABLE)
    transactions = table.scan().get('Items', [])

    # Get user and stock details for each transaction
    for transaction in transactions:
        user = get_user_by_id(transaction['user_id'])
        stock = get_stock_by_id(transaction['stock_id'])

        if user:
            transaction['user'] = user

        if stock:
            transaction['stock'] = stock

    return transactions

def get_user_by_id(user_id):
    """Get user by ID"""
    table = dynamodb.Table(USER_TABLE)
    response = table.scan(
        FilterExpression=Attr('id').eq(user_id)
    )
    items = response.get('Items', [])
    return items[0] if items else None

def get_portfolios():
    """Get all portfolios with user and stock details"""
    table = dynamodb.Table(PORTFOLIO_TABLE)
    portfolios = table.scan().get('Items', [])

    # Get user and stock details for each portfolio item
    for portfolio in portfolios:
        user = get_user_by_id(portfolio['user_id'])
        stock = get_stock_by_id(portfolio['stock_id'])

        if user:
            portfolio['user'] = user

        if stock:
            portfolio['stock'] = stock

    return portfolios

def get_user_portfolio(user_id):
    """Get portfolio for a specific user"""
    table = dynamodb.Table(PORTFOLIO_TABLE)
    response = table.query(
        KeyConditionExpression=Key('user_id').eq(user_id)
    )

    portfolio_items = response.get('Items', [])

    # Get stock details for each portfolio item
    for item in portfolio_items:
        stock = get_stock_by_id(item['stock_id'])
        if stock:
            item['stock'] = stock

    return portfolio_items

def get_user_transactions(user_id):
    """Get transactions for a specific user"""
    table = dynamodb.Table(TRANSACTION_TABLE)
    response = table.scan(
        FilterExpression=Attr('user_id').eq(user_id)
    )

    transactions = response.get('Items', [])

    # Get stock details for each transaction
    for transaction in transactions:
        stock = get_stock_by_id(transaction['stock_id'])
        if stock:
            transaction['stock'] = stock

    # Sort by transaction_date in descending order
    transactions.sort(key=lambda x: x.get('transaction_date', ''), reverse=True)

    return transactions

def get_portfolio_item(user_id, stock_id):
    """Get a specific portfolio item"""
    table = dynamodb.Table(PORTFOLIO_TABLE)
    response = table.get_item(
        Key={
            'user_id': user_id,
            'stock_id': stock_id
        }
    )
    return response.get('Item')

def create_transaction(user_id, stock_id, action, quantity, price, status='completed'):
    """Create a new transaction"""
    table = dynamodb.Table(TRANSACTION_TABLE)
    transaction_id = str(uuid.uuid4())

    transaction = {
        'id': transaction_id,
        'user_id': user_id,
        'stock_id': stock_id,
        'action': action,
        'quantity': quantity,
        'price': Decimal(str(price)),
        'status': status,
        'transaction_date': datetime.now().isoformat()
    }

    table.put_item(Item=transaction)
    return transaction

def update_portfolio(user_id, stock_id, quantity, average_price):
    """Update or create a portfolio item"""
    table = dynamodb.Table(PORTFOLIO_TABLE)

    # Ensure quantity and average_price are Decimal objects
    if not isinstance(quantity, Decimal):
        quantity = Decimal(str(quantity))

    if not isinstance(average_price, Decimal):
        average_price = Decimal(str(average_price))

    # Check if portfolio item exists
    existing = get_portfolio_item(user_id, stock_id)

    if existing and quantity > 0:
        # Update existing portfolio item
        table.update_item(
            Key={
                'user_id': user_id,
                'stock_id': stock_id
            },
            UpdateExpression="set quantity=:q, average_price=:p",
            ExpressionAttributeValues={
                ':q': quantity,
                ':p': Decimal(str(average_price))
            }
        )
    elif existing and quantity <= 0:
        # Delete portfolio item if quantity is zero or negative
        table.delete_item(
            Key={
                'user_id': user_id,
                'stock_id': stock_id
            }
        )
    elif quantity > 0:
        # Create new portfolio item
        portfolio_item = {
            'user_id': user_id,
            'stock_id': stock_id,
            'quantity': quantity,
            'average_price': Decimal(str(average_price))
        }
        table.put_item(Item=portfolio_item)
# ------------------- Routes ------------------- #
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        role = request.form.get('role')
        email = request.form.get('email')
        password = request.form.get('password')

        user = get_user_by_email(email)
        print(f"Trying to login with: {email} ({role})")

        if user and user['password'] == password and user['role'] == role:
            print("Login successful!")
            session['email'] = user['email']
            session['role'] = user['role']
            session['user_id'] = user['id']

            # Send login notification
            send_notification(
                USER_ACCOUNT_TOPIC_ARN,
                'User Login',
                f"User logged in: {user['username']} ({email}) as {role}",
                {
                    'event_type': {
                        'DataType': 'String',
                        'StringValue': 'LOGIN'
                    },
                    'user_role': {
                        'DataType': 'String',
                        'StringValue': role
                    }
                }
            )

            flash('Login successful!', 'success')
            return redirect(url_for('dashboard_admin' if role == 'admin' else 'dashboard_trader'))
        else:
            print("Login failed.")
            flash('Invalid credentials or role mismatch.', 'danger')
            return redirect(url_for('login'))

    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        role = request.form['role']

        existing_user = get_user_by_email(email)
        if existing_user:
            flash('User already exists. Please login.', 'warning')
            return redirect(url_for('login'))

        new_user = create_user(username, email, password, role)

        # Send account creation notification
        send_notification(
            USER_ACCOUNT_TOPIC_ARN,
            'New User Registration',
            f"New user registered: {username} ({email}) as {role}",
            {
                'event_type': {
                    'DataType': 'String',
                    'StringValue': 'ACCOUNT_CREATION'
                },
                'user_role': {
                    'DataType': 'String',
                    'StringValue': role
                }
            }
        )

        flash(f"Account created for {username}", 'success')
        return redirect(url_for('login'))

    return render_template('signup.html')

@app.route('/dashboard_admin')
def dashboard_admin():
    if 'email' not in session or session.get('role') != 'admin':
        flash("Access denied. Admins only.", "danger")
        return redirect(url_for('login'))

    user = get_user_by_email(session['email'])
    stocks = get_all_stocks()
    return render_template('dashboard_admin.html', user=user, market_data=stocks)

@app.route('/dashboard_trader')
def dashboard_trader():
    if 'email' not in session or session.get('role') != 'trader':
        flash("Access denied. Traders only.", "danger")
        return redirect(url_for('login'))

    user = get_user_by_email(session.get('email'))
    stocks = get_all_stocks()
    return render_template('dashboard_trader.html', user=user, market_data=stocks)

@app.route('/service01')
def service01():
    if 'email' not in session or session.get('role') != 'admin':
        flash("Access denied. Admins only.", "danger")
        return redirect(url_for('login'))      

    user = get_user_by_email(session.get('email'))
    if not user:
       session.clear()
       flash("Your account no longer exists.", "danger")
       return redirect(url_for('login')) 

    traders = get_traders()

    # Calculate portfolio values for each trader
    for trader in traders:
        trader_portfolio = get_user_portfolio(trader['id'])
        portfolio_value = 0
        for item in trader_portfolio:
            portfolio_value += float(item['quantity']) * float(item['stock']['price'])
        # Add this as an attribute to the trader object
        trader['total_portfolio_value'] = portfolio_value

    return render_template('service-details-1.html', traders=traders)   

@app.route('/delete_trader/<string:trader_id>', methods=['POST'])
def delete_trader(trader_id): 
    if 'email' not in session or session.get('role') != 'admin':
        flash("Access denied. Admins only.", "danger")
        return redirect(url_for('login'))

    user = get_user_by_email(session.get('email'))

    if not user:
       session.clear()
       flash("Your account no longer exists.", "danger")
       return redirect(url_for('login'))

    success = delete_trader_by_id(trader_id)
    if success:
        flash("Trader deleted successfully.", "success")
    else:
        flash("Failed to delete trader.", "danger")

    return redirect(url_for('service01'))

@app.route('/service02')
def service02():
    if 'email' not in session or session.get('role') != 'admin':
        flash("Access denied. Admins only.", "danger")
        return redirect(url_for('login'))

    user = get_user_by_email(session.get('email'))   
    if not user:
       session.clear()
       flash("Your account no longer exists.", "danger")
       return redirect(url_for('login'))

    transactions = get_transactions()
    for transaction in transactions:
        if 'transaction_date' in transaction and transaction['transaction_date']:
            try:
                # Convert ISO string to datetime object
                transaction['transaction_date'] = datetime.fromisoformat(transaction['transaction_date'])
            except (ValueError, TypeError):
                # If conversion fails, set to None
                transaction['transaction_date'] = None

    return render_template('service-details-2.html', transactions=transactions)

@app.route('/service03')
def service03():
    if 'email' not in session or session.get('role') != 'admin':
        flash("Access denied. Admins only.", "danger")
        return redirect(url_for('login'))

    user = get_user_by_email(session.get('email'))   
    if not user:
       session.clear()
       flash("Your account no longer exists.", "danger")
       return redirect(url_for('login'))    

    portfolios = get_portfolios()

    # Calculate total portfolio value
    total_portfolio_value = 0
    for portfolio in portfolios:
        if 'stock' in portfolio:
            total_portfolio_value += float(portfolio['quantity']) * float(portfolio['stock']['price'])

    return render_template('service-details-3.html', 
                          portfolios=portfolios, 
                          total_portfolio_value=total_portfolio_value)

@app.route('/service04')
def service04():
    if 'email' not in session or session.get('role') != 'trader':
        flash("Access denied. Traders only.", "danger")
        return redirect(url_for('login'))

    user = get_user_by_email(session.get('email'))
    if not user:
       session.clear()
       flash("Your account no longer exists.", "danger")
       return redirect(url_for('login'))

    stocks = get_all_stocks()
    return render_template('service-details-4.html', user=user, stocks=stocks)

@app.route('/service04/buy_stock/<string:stock_id>', methods=['GET', 'POST'])
def buy_stock(stock_id):
    if 'email' not in session or session.get('role') != 'trader':
        flash("Access denied. Traders only.", "danger")
        return redirect(url_for('login'))

    user = get_user_by_email(session.get('email'))   
    if not user:
       session.clear()
       flash("Your account no longer exists.", "danger")
       return redirect(url_for('login'))

    user = get_user_by_email(session.get('email'))
    stock = get_stock_by_id(stock_id)

    if not stock:
        flash("Stock not found.", "danger")
        return redirect(url_for('service04'))

    if request.method == 'POST':
        quantity = int(request.form.get('quantity', 0))

        if quantity <= 0:
            flash("Please enter a valid quantity.", "danger")
            return redirect(url_for('buy_stock', stock_id=stock_id))

        # Create transaction record
        transaction = create_transaction(
            user_id=user['id'],
            stock_id=stock_id,
            action='buy',
            quantity=quantity,
            price=float(stock['price']),
            status='completed'
        )

        # Update or create portfolio entry
        portfolio_entry = get_portfolio_item(user['id'], stock_id)

        if portfolio_entry:
            # Update existing portfolio entry
            quantity_decimal = Decimal(str(quantity))
            portfolio_quantity = Decimal(str(portfolio_entry['quantity']))
            portfolio_avg_price = Decimal(str(portfolio_entry['average_price']))
            stock_price = Decimal(str(stock['price']))

            total_value = (portfolio_quantity * portfolio_avg_price) + (quantity_decimal * stock_price)
            total_quantity = portfolio_quantity + quantity_decimal
            avg_price = total_value / total_quantity

            update_portfolio(
                user_id=user['id'],
                stock_id=stock_id,
                quantity=Decimal(str(quantity)),
                average_price=avg_price
            )
        else:
            # Create new portfolio entry
            update_portfolio(
                user_id=user['id'],
                stock_id=stock_id,
                quantity=Decimal(str(quantity)),
                average_price=Decimal(str(stock['price']))
            )

        # Send transaction notification
        send_notification(
            TRANSACTION_TOPIC_ARN,
            f"Stock Purchase: {stock['symbol']}",
            f"User {user['username']} purchased {quantity} shares of {stock['symbol']} at ₹{stock['price']} per share.",
            {
                'event_type': {
                    'DataType': 'String',
                    'StringValue': 'BUY'
                },
                'stock_symbol': {
                    'DataType': 'String',
                    'StringValue': stock['symbol']
                },
                'quantity': {
                    'DataType': 'Number',
                    'StringValue': str(quantity)
                }
            }
        )

        flash(f"Successfully purchased {quantity} shares of {stock['symbol']}!", "success")
        return redirect(url_for('service05'))

    return render_template('buy_stock.html', user=user, stock=stock)

@app.route('/service04/sell_stock/<string:stock_id>', methods=['GET', 'POST'])
def sell_stock(stock_id):
    if 'email' not in session or session.get('role') != 'trader':
        flash("Access denied. Traders only.", "danger")
        return redirect(url_for('login'))
    user = get_user_by_email(session.get('email'))
    if not user:
       session.clear()
       flash("Your account no longer exists.", "danger")
       return redirect(url_for('login'))

    user = get_user_by_email(session.get('email'))
    stock = get_stock_by_id(stock_id)

    if not stock:
        flash("Stock not found.", "danger")
        return redirect(url_for('service04'))

    # Check if user owns this stock
    portfolio_entry = get_portfolio_item(user['id'], stock_id)

    if not portfolio_entry:
        flash("You don't own any shares of this stock.", "danger")
        return redirect(url_for('service04'))

    if request.method == 'POST':
        quantity = int(request.form.get('quantity', 0))

        if quantity <= 0:
            flash("Please enter a valid quantity.", "danger")
            return redirect(url_for('sell_stock', stock_id=stock_id))

        if quantity > portfolio_entry['quantity']:
            flash("You don't have enough shares to sell.", "danger")
            return redirect(url_for('sell_stock', stock_id=stock_id))

        # Create transaction record
        transaction = create_transaction(
            user_id=user['id'],
            stock_id=stock_id,
            action='sell',
            quantity=quantity,
            price=float(stock['price']),
            status='completed'
        )

        # Update portfolio entry
        remaining_quantity = portfolio_entry['quantity'] - quantity

        update_portfolio(
            user_id=user['id'],
            stock_id=stock_id,
            quantity=remaining_quantity,
            average_price=float(portfolio_entry['average_price']) if remaining_quantity > 0 else 0
        )

        # Send transaction notification
        send_notification(
            TRANSACTION_TOPIC_ARN,
            f"Stock Purchase: {stock['symbol']}",
            f"User {user['username']} purchased {quantity} shares of {stock['symbol']} at ₹{stock['price']} per share.",
            {
                'event_type': {
                    'DataType': 'String',
                    'StringValue': 'BUY'
                },
                'stock_symbol': {
                    'DataType': 'String',
                    'StringValue': stock['symbol']
                },
                'quantity': {
                    'DataType': 'Number',
                    'StringValue': str(quantity)
                }
            }
        )

        flash(f"Successfully sold {quantity} shares of {stock['symbol']}!", "success")
        return redirect(url_for('service05'))

    return render_template('sell_stock.html', user=user, stock=stock, portfolio_entry=portfolio_entry)

# Portfolio view for traders
@app.route('/service05')
def service05():
    if 'email' not in session or session.get('role') != 'trader':
        flash("Access denied. Traders only.", "danger")
        return redirect(url_for('login'))

    user = get_user_by_email(session.get('email'))   
    if not user:
       session.clear()
       flash("Your account no longer exists.", "danger")
       return redirect(url_for('login'))

    user = get_user_by_email(session.get('email'))

    # Get portfolio with stock details
    portfolio = get_user_portfolio(user['id'])

    # Calculate total portfolio value
    total_value = 0
    try:
        for item in portfolio:
            if 'stock' in item and 'price' in item['stock'] and 'quantity' in item:
                total_value += float(item['quantity']) * float(item['stock']['price'])
    except Exception as e:
        print(f"Error calculating portfolio value: {str(e)}")
        flash("There was an issue calculating your portfolio value.", "warning")

    # Get transaction history
    transactions = get_user_transactions(user['id'])
    # Convert transaction dates to datetime objects
    for transaction in transactions:
        if 'transaction_date' in transaction and transaction['transaction_date']:
            try:
                # Convert ISO string to datetime object if it's not already
                if isinstance(transaction['transaction_date'], str):
                    transaction['transaction_date'] = datetime.fromisoformat(transaction['transaction_date'])
            except (ValueError, TypeError) as e:
                print(f"Error converting date: {str(e)}")
                # If conversion fails, set to None
                transaction['transaction_date'] = None

    return render_template('service-details-5.html', user=user, portfolio=portfolio, total_value=total_value, transactions=transactions)

@app.route('/debug/check_stocks')
def check_stocks():
    # This route will check if stocks are accessible in the database
    try:
        stocks = get_all_stocks()
        result = {
            "success": True,
            "stocks_count": len(stocks),
            "first_five": [{"id": s['id'], "symbol": s['symbol'], "name": s['name'], "price": float(s['price'])} for s in stocks[:5]]
        }
    except Exception as e:
        result = {
            "success": False,
            "error": str(e)
        }

    # Return as plain text for easy debugging
    return "<pre>" + str(result) + "</pre>"

@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('index'))

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port = 5000)
