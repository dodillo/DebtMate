from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from werkzeug.security import generate_password_hash, check_password_hash
from database import db_session, init_db
from models import User, Purchase, FriendRequest
from datetime import datetime, timedelta
from flask_wtf.csrf import CSRFProtect
from sqlalchemy.orm import joinedload
from sqlalchemy import or_, func
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import os

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', 'your_secret_key_here')  # Use environment variable for secret key
csrf = CSRFProtect(app)

# Initialize rate limiter
limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"]
)

# Initialize the database
init_db()

@app.teardown_appcontext
def shutdown_session(exception=None):
    db_session.remove()

@app.before_request
def before_request():
    db_session.rollback()
    db_session.expire_all()

def get_pending_requests_count(user_id):
    return FriendRequest.query.filter(
        (FriendRequest.receiver_id == user_id) &
        (FriendRequest.status == 'pending')
    ).count()

@app.route('/')
def landing():
    if 'user_id' in session:
        return redirect(url_for('tracker'))
    return render_template('landing.html')

@app.route('/home')
def index():
    if 'user_id' in session:
        return redirect(url_for('tracker'))
    return redirect(url_for('landing'))

@app.route('/signup', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def signup():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')
        name = request.form['name']

        existing_user = User.query.filter_by(username=username).first()
        if existing_user:
            flash('Username already exists. Please choose a different one.', 'error')
        else:
            new_user = User(username=username, password=generate_password_hash(password), name=name)
            db_session.add(new_user)
            db_session.commit()
            flash('Account created successfully. Please log in.', 'success')
            return redirect(url_for('login'))

    pending_requests_count = 0  # No pending requests before login
    return render_template('signup.html', pending_requests_count=pending_requests_count)

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("10 per minute")
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']

        user = User.query.filter_by(username=username).first()
        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            flash('Logged in successfully.', 'success')
            return redirect(url_for('tracker'))
        else:
            flash('Invalid username or password.', 'error')

    pending_requests_count = 0  # No pending requests before login
    return render_template('login.html', pending_requests_count=pending_requests_count)

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash('Logged out successfully.', 'success')
    return redirect(url_for('login'))

@app.route('/tracker', methods=['GET', 'POST'])
def tracker():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user = User.query.options(joinedload(User.friends)).get(session['user_id'])
    purchases = Purchase.query.filter(
        (Purchase.buyer_id == session['user_id']) |
        (Purchase.concerned_user_id == session['user_id'])
    ).order_by(Purchase.date.desc()).all()

    for purchase in purchases:
        purchase.date = purchase.date + timedelta(hours=1)

    # Calculate balances
    balances = {}
    for purchase in purchases:
        if purchase.buyer_id == session['user_id']:
            balances[purchase.concerned_user_id] = balances.get(purchase.concerned_user_id, 0) + purchase.amount
        elif purchase.concerned_user_id == session['user_id']:
            balances[purchase.buyer_id] = balances.get(purchase.buyer_id, 0) - purchase.amount

    # Handle adding a purchase
    if request.method == 'POST':
        item = request.form['item']
        amount = float(request.form['amount'])
        concerned_user_id = int(request.form['concerned_user'])

        if concerned_user_id in [friend.id for friend in user.friends]:
            new_purchase = Purchase(item=item, amount=amount, buyer_id=session['user_id'], concerned_user_id=concerned_user_id, date=datetime.utcnow())
            db_session.add(new_purchase)
            db_session.commit()
            flash('Purchase added successfully!', 'success')
        else:
            flash('You can only add purchases for your friends.', 'error')
        return redirect(url_for('tracker'))

    pending_requests_count = get_pending_requests_count(session['user_id'])
    return render_template('tracker.html', user=user, purchases=purchases, user_balances=balances, pending_requests_count=pending_requests_count)

@app.route('/account')
def account():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user = User.query.options(joinedload(User.friends)).get(session['user_id'])
    friend_requests = FriendRequest.query.filter(
        (FriendRequest.receiver_id == session['user_id']) &
        (FriendRequest.status == 'pending')
    ).all()

    pending_requests_count = len(friend_requests)

    return render_template('account.html', user=user, friend_requests=friend_requests, pending_requests_count=pending_requests_count)

@app.route('/send_friend_request', methods=['POST'])
@limiter.limit("10 per minute")
def send_friend_request():
    if 'user_id' not in session:
        return jsonify({"error": "Unauthorized"}), 401

    friend_username = request.json.get('friend_username')
    friend = User.query.filter_by(username=friend_username).first()

    if not friend:
        return jsonify({"error": "User not found"}), 404

    user = User.query.get(session['user_id'])
    if friend in user.friends:
        return jsonify({"error": "Already friends"}), 400

    existing_request = FriendRequest.query.filter_by(sender_id=user.id, receiver_id=friend.id, status='pending').first()
    if existing_request:
        return jsonify({"error": "Friend request already sent"}), 400

    new_request = FriendRequest(sender_id=user.id, receiver_id=friend.id, created_at=datetime.utcnow())
    db_session.add(new_request)
    db_session.commit()

    return jsonify({"message": "Friend request sent successfully"}), 200

@app.route('/accept_friend_request/<int:request_id>', methods=['POST'])
def accept_friend_request(request_id):
    if 'user_id' not in session:
        return jsonify({"error": "Unauthorized"}), 401

    friend_request = FriendRequest.query.get(request_id)
    if not friend_request or friend_request.receiver_id != session['user_id']:
        return jsonify({"error": "Friend request not found"}), 404

    user = User.query.get(session['user_id'])
    friend = User.query.get(friend_request.sender_id)

    user.friends.append(friend)
    friend.friends.append(user)  # Make the relationship bidirectional
    friend_request.status = 'accepted'
    db_session.commit()

    return jsonify({"message": "Friend request accepted"}), 200

@app.route('/reject_friend_request/<int:request_id>', methods=['POST'])
def reject_friend_request(request_id):
    if 'user_id' not in session:
        return jsonify({"error": "Unauthorized"}), 401

    friend_request = FriendRequest.query.get(request_id)
    if not friend_request or friend_request.receiver_id != session['user_id']:
        return jsonify({"error": "Friend request not found"}), 404

    friend_request.status = 'rejected'
    db_session.commit()

    return jsonify({"message": "Friend request rejected"}), 200

@app.route('/edit_purchase/<int:id>', methods=['POST'])
def edit_purchase(id):
    if 'user_id' not in session:
        return jsonify({"error": "Unauthorized"}), 401

    purchase = Purchase.query.get(id)
    if not purchase or (purchase.buyer_id != session['user_id'] and purchase.concerned_user_id != session['user_id']):
        return jsonify({"error": "Purchase not found or you don't have permission to edit it"}), 404

    data = request.json
    purchase.item = data.get('item', purchase.item)
    purchase.amount = float(data.get('amount', purchase.amount))
    db_session.commit()

    return jsonify({"message": "Purchase updated successfully"}), 200

@app.route('/delete_purchase/<int:id>', methods=['POST'])
def delete_purchase(id):
    if 'user_id' not in session:
        return jsonify({"error": "Unauthorized"}), 401

    purchase = Purchase.query.get(id)
    if not purchase or (purchase.buyer_id != session['user_id'] and purchase.concerned_user_id != session['user_id']):
        return jsonify({"error": "Purchase not found or you don't have permission to delete it"}), 404

    db_session.delete(purchase)
    db_session.commit()

    return jsonify({"message": "Purchase deleted successfully"}), 200

@app.route('/analytics')
def analytics():
    if 'user_id' not in session:
        return redirect(url_for('login'))

    user_id = session['user_id']

    # Total spent
    total_spent = db_session.query(func.sum(Purchase.amount)).filter(Purchase.buyer_id == user_id).scalar() or 0

    # Total owed
    total_owed = db_session.query(func.sum(Purchase.amount)).filter(Purchase.concerned_user_id == user_id).scalar() or 0

    # Purchases by category
    purchases_by_category = db_session.query(
        Purchase.category, func.sum(Purchase.amount)
    ).filter(
        (Purchase.buyer_id == user_id) | (Purchase.concerned_user_id == user_id)
    ).group_by(Purchase.category).all()

    # Monthly spending trend
    monthly_spending = db_session.query(
        func.strftime('%Y-%m', Purchase.date).label('month'),
        func.sum(Purchase.amount)
    ).filter(
        (Purchase.buyer_id == user_id) | (Purchase.concerned_user_id == user_id)
    ).group_by('month').order_by('month').all()

    return render_template('analytics.html',
                           total_spent=total_spent,
                           total_owed=total_owed,
                           purchases_by_category=purchases_by_category,
                           monthly_spending=monthly_spending)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080, debug=True)  # Set debug to False in production