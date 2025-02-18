from flask import Flask, render_template, request, redirect, url_for, flash
import hashlib
import re
import uuid
from boto3 import resource
from boto3.dynamodb.conditions import Key
from datetime import datetime

app = Flask(__name__)
app.secret_key = 'your_secret_key'

# Connect to the AWS DynamoDB table
db = resource('dynamodb', region_name='us-east-2').Table('usersDB')

def get_time():
    return datetime.now().isoformat()

def hash_password(password):
    return hashlib.sha256(password.encode('utf-8')).hexdigest()

def username_availability(username):
    response = db.query(KeyConditionExpression=Key('username').eq(username))
    return bool(response['Items'])

def password_validity_check(password):
    return (len(password) >= 8 and
            re.search('[a-z]', password) and
            re.search('[A-Z]', password) and
            re.search('[0-9]', password) and
            re.search('[$@#%^&*()_+!]', password))

def create_UUID():
    return str(uuid.uuid4())

def register_user_into_dynamo(username, UUID, hashed_password, role,
                              full_name, email, phone_number, pet_name,
                              grade, subjects, availability, created_at, updated_at):
    db.put_item(Item={
        'username': username,  
        'user_id': UUID,
        'password': hashed_password,
        'role': role,
        'full_name': full_name,
        'email': email,
        'phone_number': phone_number,
        'pet_name': pet_name,
        'grade': grade,
        'subjects': subjects,
        'availability': availability,
        'created_at': created_at,
        'updated_at': updated_at,
    })

@app.route('/')
def index():
    return render_template('login.html')

@app.route('/login', methods=['POST'])
def login():
    username = request.form['username']
    password = request.form['password']
    if validate_user_login(username, password):
        return redirect(url_for('home', username=username))
    else:
        flash('Invalid username or password')
        return redirect(url_for('index'))

def validate_user_login(username, input_password):
    response = db.query(KeyConditionExpression=Key('username').eq(username))
    if not response['Items']:
        return False

    user_item = response['Items'][0]
    stored_hashed_password = user_item.get('password')
    input_hashed_password = hash_password(input_password)

    return input_hashed_password == stored_hashed_password

@app.route('/home/<username>')
def home(username):
    return render_template('home.html', username=username)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if username_availability(username):
            flash('Username already exists')
            return redirect(url_for('register'))

        if password_validity_check(password):
            password2 = request.form['password2']
            if password == password2:
                hashed_password = hash_password(password)
                email = request.form['email']
                phone_number = request.form['phone_number']
                pet_name = request.form['pet_name']
                role = request.form['role']
                full_name = request.form['full_name']
                grade = request.form['grade']
                subjects = request.form['subjects']
                availability = request.form['availability']
                created_at = updated_at = get_time()

                UUID = create_UUID()

                register_user_into_dynamo(username, UUID, hashed_password, role,
                                          full_name, email, phone_number, pet_name,
                                          grade, subjects, availability, created_at, updated_at)
                flash('Registration Successful')
                return redirect(url_for('index'))
            else:
                flash('Passwords do not match')
        else:
            flash('Password must meet the complexity requirements')

    return render_template('register.html')

@app.route('/recover', methods=['GET', 'POST'])
def recover():
    if request.method == 'POST':
        username = request.form['username']
        if not username_availability(username):
            flash("Username not found")
            return redirect(url_for('recover'))

        pet_name = request.form['pet_name']
        if validate_pet_name(username, pet_name):
            new_password = request.form['new_password']
            if password_validity_check(new_password):
                hashed_new_password = hash_password(new_password)
                update_password_in_dynamo(username, hashed_new_password)
                flash('Password updated successfully')
                return redirect(url_for('index'))
            else:
                flash('Invalid password format')
        else:
            flash('Incorrect pet name')

    return render_template('recover.html')

def validate_pet_name(username, pet_name):
    response = db.query(KeyConditionExpression=Key('username').eq(username))
    user_item = response['Items'][0]
    db_pet_name = user_item.get('pet_name')
    return pet_name.lower() == db_pet_name.lower()

def update_password_in_dynamo(username, new_hashed_password):
    db.update_item(
        Key={'username': username},
        UpdateExpression='set #password=:s, updated_at=:n',
        ExpressionAttributeValues={
            ':s': new_hashed_password,
            ':n': datetime.now().isoformat(),
        },
        ExpressionAttributeNames={'#password': 'password'},
        ReturnValues="UPDATED_NEW"
    )

if __name__ == '__main__':
    app.run(debug=True)
