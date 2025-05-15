import sqlite3
from datetime import datetime

def init_db():
    with sqlite3.connect('p2p.db') as conn:
        c = conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS users
                     (username TEXT PRIMARY KEY, password_hash TEXT, node_id TEXT, public_key BLOB, address TEXT, peer_id TEXT)''')
        c.execute('''CREATE TABLE IF NOT EXISTS resources
                     (filename TEXT, category TEXT, file_hash TEXT, owner TEXT, aes_key BLOB, timestamp TEXT, cid TEXT)''')
        c.execute('''CREATE TABLE IF NOT EXISTS messages
                     (id INTEGER PRIMARY KEY AUTOINCREMENT, sender TEXT, recipient TEXT, content TEXT, timestamp TEXT)''')
        c.execute('''CREATE TABLE IF NOT EXISTS usage
                     (username TEXT, action TEXT, timestamp TEXT)''')
        conn.commit()

def register_user(username, password_hash, node_id, public_key, address, peer_id):
    with sqlite3.connect('p2p.db') as conn:
        c = conn.cursor()
        try:
            c.execute('INSERT INTO users (username, password_hash, node_id, public_key, address, peer_id) VALUES (?, ?, ?, ?, ?, ?)',
                      (username, password_hash, node_id, public_key, address, peer_id))
            conn.commit()
            return True
        except sqlite3.IntegrityError:
            return False

def verify_user(username, password_hash):
    with sqlite3.connect('p2p.db') as conn:
        c = conn.cursor()
        c.execute('SELECT password_hash FROM users WHERE username = ?', (username,))
        result = c.fetchone()
        return result and result[0] == password_hash

def get_user_address(username):
    with sqlite3.connect('p2p.db') as conn:
        c = conn.cursor()
        c.execute('SELECT address FROM users WHERE username = ?', (username,))
        result = c.fetchone()
        return result[0] if result else None

def get_user_peer_id(username):
    with sqlite3.connect('p2p.db') as conn:
        c = conn.cursor()
        c.execute('SELECT peer_id FROM users WHERE username = ?', (username,))
        result = c.fetchone()
        return result[0] if result else None

def store_resource(filename, category, file_hash, owner, aes_key, cid):
    with sqlite3.connect('p2p.db') as conn:
        c = conn.cursor()
        timestamp = datetime.utcnow().isoformat()
        c.execute('INSERT INTO resources (filename, category, file_hash, owner, aes_key, timestamp, cid) VALUES (?, ?, ?, ?, ?, ?, ?)',
                  (filename, category, file_hash, owner, aes_key, timestamp, cid))
        conn.commit()

def get_resources(category=None, search=None):
    with sqlite3.connect('p2p.db') as conn:
        c = conn.cursor()
        query = 'SELECT filename, category, file_hash, owner, timestamp FROM resources'
        params = []
        conditions = []
        if category:
            conditions.append('category = ?')
            params.append(category)
        if search:
            conditions.append('filename LIKE ?')
            params.append(f'%{search}%')
        if conditions:
            query += ' WHERE ' + ' AND '.join(conditions)
        c.execute(query, params)
        return c.fetchall()

def get_resource_key(filename):
    with sqlite3.connect('p2p.db') as conn:
        c = conn.cursor()
        c.execute('SELECT aes_key, owner, cid FROM resources WHERE filename = ?', (filename,))
        result = c.fetchone()
        return result if result else (None, None, None)

def store_message(sender, recipient, content):
    with sqlite3.connect('p2p.db') as conn:
        c = conn.cursor()
        timestamp = datetime.utcnow().isoformat()
        c.execute('INSERT INTO messages (sender, recipient, content, timestamp) VALUES (?, ?, ?, ?)',
                  (sender, recipient, content, timestamp))
        conn.commit()

def get_messages(username):
    with sqlite3.connect('p2p.db') as conn:
        c = conn.cursor()
        c.execute('SELECT sender, recipient, content, timestamp FROM messages WHERE sender = ? OR recipient = ? ORDER BY timestamp DESC',
                  (username, username))
        return c.fetchall()

def get_all_users():
    with sqlite3.connect('p2p.db') as conn:
        c = conn.cursor()
        c.execute('SELECT username FROM users')
        return [row[0] for row in c.fetchall()]

def log_usage(username, action):
    with sqlite3.connect('p2p.db') as conn:
        c = conn.cursor()
        timestamp = datetime.utcnow().isoformat()
        c.execute('INSERT INTO usage (username, action, timestamp) VALUES (?, ?, ?)',
                  (username, action, timestamp))
        conn.commit()