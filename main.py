import bcrypt
import sqlite3
import pandas as pd

from app_model.schema import create_user_table

from app_model.db import conn
from app_model.users import add_user, get_user
from hashing import generate_hash, is_valid_hash

# hashed using bcrypt
def generate_hash(psw):
    byte_psw = psw.encode('utf-8')
    salt = bcrypt.gensalt()
    hash = bcrypt.hashpw(byte_psw, salt)
    return hash.decode('utf-8')


# validating hash vs psw
def is_valid_hash(psw, hash):
    hash_ = hash.encode('utf-8')
    byte_psw = psw.encode('utf-8')
    is_valid = bcrypt.checkpw(byte_psw, hash_)
    return is_valid


# user registration
def register_user(conn):
    name = input('Enter your name: > ')
    password = input('Enter your password: > ')
    hash_password = generate_hash(password)
    add_user(conn, name, hash_password)


# user log in
def log_in_user(conn):
    name = input('Enter your name: > ')
    password = input('Enter your password: > ')
    id, user_name, user_hash = get_user(conn, name)
    print(f'Welcome {user_name} !!')
    if name == user_name and is_valid_hash(password, user_hash):
        return True
    return False


def main():
    while True:
        print('Welcome to the system!!')
        print('Choose from the following options:')
        print('1. To Register')
        print('2. To Log in')
        print('3. To Exit :')

        choice = input(': > ')

        if choice == '1':
            register_user(conn)

        elif choice == '2':
            if log_in_user(conn):
                print('Log in successfully!')
            else:
                print('Incorrect log in. Try again !')

        elif choice == '3':
            print('Good bye!!')
            break


if __name__ == '__main__':
    main()

