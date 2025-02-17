import hashlib
import re
import json
import os
from boto3 import resource 
from boto3.dynamodb.conditions import Attr, Key 
from datetime import datetime
import uuid

#connect to the aws table 
db = resource('dynamodb', region_name='us-east-2').Table('usersDB')

def display():
    print('''
-----------------------------Start Menu-----------------------------

Press 1 to login
Press 2 to register
Press 3 to recover your password
-------------------------------------------------------------------
''')
    choice = input('Enter a number: ').strip()
    if choice == '1':
        login()
    elif choice == '2':
        register()
    elif choice == '3':
        recover()
    else:
        print('Invalid choice')
        display()


def register_user_into_dynamo(username, UUID, hashed_password, role, 
                              full_name, email, phone_number, pet_name, 
                              grade, subjects, availibility, created_at, updated_at):
    
    print(f'demo_insert')
    response = db.put_item(
        Item={
            
            #add a function that makes unique uids, orderid could be the uid 
            'username':username, #partition key - PK an SK in usersDB
            'user_id': UUID, 
            'password':hashed_password,
            'role':role,
            'full_name':full_name,
            'email':email,
            'phone_number':phone_number,
            'pet_name':pet_name,
            
            'grade':grade,
            'subjects':subjects,
            'availability':availibility,
            
            'created_at': created_at,
            'updated_at': updated_at,   
            }
        )
    print(f'Insert respone: {response}')

# Function to update password
def update_password_in_dynamo(username, new_hashed_password):
    response = {}
    response = db.update_item(
        Key={
            'username': username,
        },
        UpdateExpression='set #password=:s, updated_at=:n',
        ExpressionAttributeValues={
            ':s': new_hashed_password,
            ':n': datetime.now().isoformat()
        },
        ExpressionAttributeNames={
            '#password': 'password'
        },
        ReturnValues="UPDATED_NEW"
    )
    print('Password updated successfully')


def get_time():
    time = datetime.now().isoformat()
    return time

def register():
    username = input('Enter your username: ')
    password = input('Enter your password: ')


    if  username_availibility(username):
        print('Username already exists')
        register()
    elif password_validity_check(password):
        password2 = input('Enter password again: ')
        
        if password == password2:
            hashed_password = hash_password(password)
            email = input('Enter your email: ')
            phone_number = input('Enter your phone number: ')
            pet_name = input('Enter pet name for password recovery: ')
            
            role = input('Enter your role: ') ##make button
            full_name = input('Enter your full name: ')
            grade = input('Enter your grade: ')
            subjects = input('Enter your subjects: ')
            availibility = input('Enter your availability: ')
            created_at = get_time()
            updated_at = get_time()
            
            UUID=create_UUID()
            
            register_user_into_dynamo(username, UUID, hashed_password, role, 
                              full_name, email, phone_number, pet_name, 
                              grade, subjects, availibility, created_at, updated_at)    
            
            print('Registration Successful')
            display()
        else:
            print('Passwords do not match')
            register()
    else:
        print('Password must be 8 characters long and contain at least one uppercase letter, one lowercase letter, one number, and one special character')
        register()

def username_availibility(username):
    
    response = {}

    filtering_exp = Key('username').eq(username)
    response = db.query(
        KeyConditionExpression=filtering_exp)   
    
    # Check if the user exists
    if response['Items']:
        return True
    
    
def password_validity_check(password):
    return (len(password) >= 8 and
            re.search('[a-z]', password) and
            re.search('[A-Z]', password) and
            re.search('[0-9]', password) and
            re.search('[$@#%^&*()_+!]', password))

def create_UUID():
    myuuid = uuid.uuid4()
    return str(myuuid)

def login():
    username = input("Enter your username: ")
    password = input('Enter your password: ')

    validate_user_login(username, password) 
    display()
    

def validate_user_login(username, input_password):
    print(f"Validating login for user: {username}")

    # Query to find the user by username
    
    response = {}

    filtering_exp = Key('username').eq(username)
    response = db.query(
        KeyConditionExpression=filtering_exp)   
    
    # Check if the user exists
    if not response['Items']:
        print("User not found")
        return False

    # Get the first matching item (assuming username is unique)
    user_item = response['Items'][0]
    stored_hashed_password = user_item.get('password')  # Assuming 'password' is the attribute storing the hashed password

    # Hash the input password and compare
    input_hashed_password = hash_password(input_password)

    if input_hashed_password == stored_hashed_password:
        print("Login successful")
        return True
    else:
        print("Incorrect password")
        return False
    
def validate_pet_name(username, pet_name):

    # Query to find the user by username
    
    response = {}

    filtering_exp = Key('username').eq(username)
    response = db.query(
        KeyConditionExpression=filtering_exp)   
    
    # Get the first matching item (assuming username is unique)
    user_item = response['Items'][0]

    # Retrieve the pet name from the item (assuming 'pet_name' is the attribute for the pet name)
    db_pet_name = user_item.get('pet_name')

    if pet_name.lower()==db_pet_name.lower():
        print(f"User's pet name is: {pet_name}")
        return True
    else:
        print("Pet name not found for this user")
        return None
    
def get_user_password(username):
    response = {}

    filtering_exp = Key('username').eq(username)
    response = db.query(
        KeyConditionExpression=filtering_exp)   
    user_item = response['Items'][0]
    stored_hashed_password = user_item.get('password')  # Assuming 'password' is the attribute storing the hashed password
    return stored_hashed_password
    
    
def recover():
    username = input("Enter your username: ")
    
    #check if username is in db 
    if not username_availibility(username):
        print("Username not found")
        recover()
    
    #figure out how to send email..? 
    pet_name = input('Enter the name of your pet: ')
    if validate_pet_name(username,pet_name):
        new_password = input('Enter a new password: ')
        if password_validity_check(new_password):
            hashed_new_password = hash_password(new_password)
            
            if hashed_new_password == get_user_password(username):
                print('Cannot choose current password')
                recover()
                
            else:
                update_password_in_dynamo(username, hashed_new_password)
                display()
        else:
            print("Invalid password format")
            recover()
    else:
        print('Incorrect pet name')
        recover()
    #display()


def hash_password(n):
    return hashlib.sha256(n.encode('utf-8')).hexdigest()


def menu(username):
    print('Press 1 to record audio')
    print('Press 2 to upload audio')
    print('Press 3 to view old data')
    choice = input('Enter a number: ').strip()
    if choice in ['1', '2', '3']:
        print(f"Selected option {choice}")
    else:
        print("Invalid choice")
        menu(username)


display()





