import sqlite3
import logging
import os
from security import hash_password, verify_password

def get_db_connection():
    conn = sqlite3.connect('database.db')
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                email TEXT PRIMARY KEY,
                password TEXT NOT NULL,
                address TEXT NOT NULL,
                port INTEGER NOT NULL,
                public_key TEXT NOT NULL,
                private_key TEXT NOT NULL
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS resources (
                filename TEXT PRIMARY KEY,
                category TEXT NOT NULL,
                file_hash TEXT NOT NULL,
                owner_email TEXT NOT NULL,
                FOREIGN KEY (owner_email) REFERENCES users (email)
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS messages (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                sender_email TEXT NOT NULL,
                recipient_email TEXT NOT NULL,
                content TEXT NOT NULL,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (sender_email) REFERENCES users (email),
                FOREIGN KEY (recipient_email) REFERENCES users (email)
            )
        ''')
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS usage_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT NOT NULL,
                action TEXT NOT NULL,
                timestamp DATETIME NOT NULL,
                FOREIGN KEY (email) REFERENCES users (email)
            )
        ''')
        conn.commit()
        logging.info("Database initialized successfully")
    except Exception as e:
        logging.error(f"Failed to initialize database: {str(e)}")
        raise
    finally:
        conn.close()

def register_user(email, password, address, port, public_key, private_key):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT email FROM users WHERE email = ?', (email,))
        if cursor.fetchone():
            conn.close()
            raise ValueError(f"Email {email} is already registered")
        logging.debug(f"Registering user {email} with types: email={type(email)}, password={type(password)}, address={type(address)}, port={type(port)}, public_key={type(public_key)}, private_key={type(private_key)}")
        cursor.execute('''
            INSERT INTO users (email, password, address, port, public_key, private_key)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (email, password, address, port, public_key, private_key))
        conn.commit()
        logging.debug(f"User {email} registered successfully with port {port}")
    except Exception as e:
        logging.error(f"Failed to register user {email}: {str(e)}")
        raise
    finally:
        conn.close()

def verify_user(email, password):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM users WHERE email = ?', (email,))
        user = cursor.fetchone()
        conn.close()
        if user:
            if verify_password(password, user['password']):
                logging.debug(f"User {email} verified successfully")
                return user
            else:
                logging.debug(f"Password verification failed for {email}")
        else:
            logging.debug(f"User {email} not found")
        return None
    except Exception as e:
        logging.error(f"Failed to verify user {email}: {str(e)}")
        return None

def store_resource(filename, category, file_hash, owner_email):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO resources (filename, category, file_hash, owner_email)
            VALUES (?, ?, ?, ?)
        ''', (filename, category, file_hash, owner_email))
        conn.commit()
        logging.debug(f"Resource {filename} stored for {owner_email}")
    except Exception as e:
        logging.error(f"Failed to store resource {filename}: {str(e)}")
        raise
    finally:
        conn.close()

def get_resources():
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT filename, category, file_hash, owner_email FROM resources')
        resources = cursor.fetchall()
        conn.close()
        return resources
    except Exception as e:
        logging.error(f"Failed to retrieve resources: {str(e)}")
        return []

def get_resource_key(filename):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT file_hash FROM resources WHERE filename = ?', (filename,))
        resource = cursor.fetchone()
        conn.close()
        return resource['file_hash'] if resource else None
    except Exception as e:
        logging.error(f"Failed to retrieve resource key for {filename}: {str(e)}")
        return None

def store_message(sender_email, recipient_email, content):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO messages (sender_email, recipient_email, content)
            VALUES (?, ?, ?)
        ''', (sender_email, recipient_email, content))
        conn.commit()
        logging.debug(f"Message from {sender_email} to {recipient_email} stored")
    except Exception as e:
        logging.error(f"Failed to store message from {sender_email} to {recipient_email}: {str(e)}")
        raise
    finally:
        conn.close()

def get_messages(recipient_email):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('''
            SELECT sender_email, content, timestamp
            FROM messages
            WHERE recipient_email = ?
            ORDER BY timestamp DESC
        ''', (recipient_email,))
        messages = cursor.fetchall()
        conn.close()
        return [{'sender': m['sender_email'], 'content': m['content'], 'timestamp': m['timestamp']} for m in messages]
    except Exception as e:
        logging.error(f"Failed to retrieve messages for {recipient_email}: {str(e)}")
        return []

def get_all_users():
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT email FROM users')
        users = cursor.fetchall()
        conn.close()
        return [user['email'] for user in users]
    except Exception as e:
        logging.error(f"Failed to retrieve users: {str(e)}")
        return []

def log_usage(email, action, timestamp):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO usage_logs (email, action, timestamp)
            VALUES (?, ?, ?)
        ''', (email, action, timestamp))
        conn.commit()
        logging.debug(f"Logged action {action} for {email}")
    except Exception as e:
        logging.error(f"Failed to log usage for {email}: {str(e)}")
        raise
    finally:
        conn.close()

def get_user_address(email):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT address FROM users WHERE email = ?', (email,))
        user = cursor.fetchone()
        conn.close()
        return user['address'] if user else None
    except Exception as e:
        logging.error(f"Failed to retrieve address for {email}: {str(e)}")
        return None

def get_user_port(email):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT port FROM users WHERE email = ?', (email,))
        user = cursor.fetchone()
        conn.close()
        return user['port'] if user else None
    except Exception as e:
        logging.error(f"Failed to retrieve port for {email}: {str(e)}")
        return None

def get_user_private_key(email):
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT private_key FROM users WHERE email = ?', (email,))
        user = cursor.fetchone()
        conn.close()
        return user['private_key'] if user else None
    except Exception as e:
        logging.error(f"Failed to retrieve private key for {email}: {str(e)}")
        return None

def get_used_ports():
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        cursor.execute('SELECT port FROM users')
        ports = cursor.fetchall()
        conn.close()
        return [port['port'] for port in ports]
    except Exception as e:
        logging.error(f"Failed to retrieve used ports: {str(e)}")
        return []