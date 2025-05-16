import sqlite3
import logging

logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

def init_db():
    """Initialize the SQLite database and create necessary tables."""
    try:
        with sqlite3.connect('p2p.db') as conn:
            c = conn.cursor()
            c.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    username TEXT PRIMARY KEY,
                    password_hash TEXT NOT NULL,
                    node_id TEXT NOT NULL,
                    public_key TEXT NOT NULL,
                    address TEXT NOT NULL,
                    peer_id TEXT NOT NULL,
                    port INTEGER NOT NULL,
                    private_key TEXT
                )
            ''')
            c.execute('''
                CREATE TABLE IF NOT EXISTS resources (
                    filename TEXT NOT NULL,
                    category TEXT NOT NULL,
                    file_hash TEXT NOT NULL,
                    owner TEXT NOT NULL,
                    aes_key BLOB,
                    public_key TEXT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    PRIMARY KEY (filename, owner),
                    FOREIGN KEY (owner) REFERENCES users(username)
                )
            ''')
            c.execute('''
                CREATE TABLE IF NOT EXISTS messages (
                    sender TEXT NOT NULL,
                    recipient TEXT NOT NULL,
                    content TEXT NOT NULL,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (sender) REFERENCES users(username),
                    FOREIGN KEY (recipient) REFERENCES users(username)
                )
            ''')
            c.execute('''
                CREATE TABLE IF NOT EXISTS usage_log (
                    username TEXT NOT NULL,
                    action TEXT NOT NULL,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (username) REFERENCES users(username)
                )
            ''')
            conn.commit()
            logging.info("Database initialized successfully")
    except sqlite3.Error as e:
        logging.error(f"Database initialization failed: {str(e)}")
        raise

def register_user(username, password_hash, node_id, public_key, address, peer_id, port, private_key=None):
    """Register a new user in the database."""
    try:
        with sqlite3.connect('p2p.db') as conn:
            c = conn.cursor()
            c.execute('''
                INSERT INTO users (username, password_hash, node_id, public_key, address, peer_id, port, private_key)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ''', (username, password_hash, node_id, public_key, address, peer_id, port, private_key))
            conn.commit()
            logging.debug(f"User {username} registered with port {port}")
            return True
    except sqlite3.IntegrityError:
        logging.warning(f"User {username} already exists")
        return False
    except sqlite3.Error as e:
        logging.error(f"Failed to register user {username}: {str(e)}")
        return False

def verify_user(username, password_hash):
    """Verify user credentials."""
    try:
        with sqlite3.connect('p2p.db') as conn:
            c = conn.cursor()
            c.execute('SELECT password_hash FROM users WHERE username = ?', (username,))
            result = c.fetchone()
            if result and result[0] == password_hash:
                return True
            logging.debug(f"Verification failed for {username}")
            return False
    except sqlite3.Error as e:
        logging.error(f"Failed to verify user {username}: {str(e)}")
        return False

def get_user_private_key(username):
    """Retrieve the private key for a user."""
    try:
        with sqlite3.connect('p2p.db') as conn:
            c = conn.cursor()
            c.execute('SELECT private_key FROM users WHERE username = ?', (username,))
            result = c.fetchone()
            if result and result[0]:
                return result[0]
            logging.debug(f"No private key found for {username}")
            return None
    except sqlite3.Error as e:
        logging.error(f"Failed to retrieve private key for {username}: {str(e)}")
        return None

def store_resource(filename, category, file_hash, owner, aes_key, public_key):
    """Store resource metadata in the database."""
    try:
        with sqlite3.connect('p2p.db') as conn:
            c = conn.cursor()
            c.execute('''
                INSERT OR REPLACE INTO resources (filename, category, file_hash, owner, aes_key, public_key)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (filename, category, file_hash, owner, aes_key, public_key))
            conn.commit()
            logging.debug(f"Resource {filename} stored for {owner}")
    except sqlite3.Error as e:
        logging.error(f"Failed to store resource {filename}: {str(e)}")
        raise

def get_resources(category='', search=''):
    """Retrieve resources from the database, optionally filtered by category or search term."""
    try:
        with sqlite3.connect('p2p.db') as conn:
            c = conn.cursor()
            query = 'SELECT filename, category, file_hash, owner, timestamp FROM resources WHERE 1=1'
            params = []
            if category:
                query += ' AND category = ?'
                params.append(category)
            if search:
                query += ' AND filename LIKE ?'
                params.append(f'%{search}%')
            c.execute(query, params)
            return c.fetchall()
    except sqlite3.Error as e:
        logging.error(f"Failed to retrieve resources: {str(e)}")
        return []

def get_resource_key(file_hash):
    """Retrieve the AES key for a resource by its file hash."""
    try:
        with sqlite3.connect('p2p.db') as conn:
            c = conn.cursor()
            c.execute('SELECT aes_key FROM resources WHERE file_hash = ?', (file_hash,))
            result = c.fetchone()
            if result:
                return result[0]
            logging.debug(f"No AES key found for file_hash {file_hash}")
            return None
    except sqlite3.Error as e:
        logging.error(f"Failed to retrieve AES key for file_hash {file_hash}: {str(e)}")
        return None

def store_message(sender, recipient, content):
    """Store a message in the database."""
    try:
        with sqlite3.connect('p2p.db') as conn:
            c = conn.cursor()
            c.execute('''
                INSERT INTO messages (sender, recipient, content)
                VALUES (?, ?, ?)
            ''', (sender, recipient, content))
            conn.commit()
            logging.debug(f"Message from {sender} to {recipient} stored")
    except sqlite3.Error as e:
        logging.error(f"Failed to store message from {sender} to {recipient}: {str(e)}")
        raise

def get_messages(username):
    """Retrieve messages for a user."""
    try:
        with sqlite3.connect('p2p.db') as conn:
            c = conn.cursor()
            c.execute('''
                SELECT sender, recipient, content, timestamp
                FROM messages
                WHERE recipient = ? OR sender = ?
                ORDER BY timestamp
            ''', (username, username))
            return c.fetchall()
    except sqlite3.Error as e:
        logging.error(f"Failed to retrieve messages for {username}: {str(e)}")
        return []

def get_all_users():
    """Retrieve all registered users."""
    try:
        with sqlite3.connect('p2p.db') as conn:
            c = conn.cursor()
            c.execute('SELECT username FROM users')
            return [row[0] for row in c.fetchall()]
    except sqlite3.Error as e:
        logging.error(f"Failed to retrieve users: {str(e)}")
        return []

def log_usage(username, action):
    """Log user actions in the database."""
    try:
        with sqlite3.connect('p2p.db') as conn:
            c = conn.cursor()
            c.execute('''
                INSERT INTO usage_log (username, action)
                VALUES (?, ?)
            ''', (username, action))
            conn.commit()
            logging.debug(f"Logged action {action} for {username}")
    except sqlite3.Error as e:
        logging.error(f"Failed to log action for {username}: {str(e)}")
        raise

def get_user_address(username):
    """Retrieve the address for a user."""
    try:
        with sqlite3.connect('p2p.db') as conn:
            c = conn.cursor()
            c.execute('SELECT address FROM users WHERE username = ?', (username,))
            result = c.fetchone()
            if result:
                return result[0]
            logging.debug(f"No address found for {username}")
            return None
    except sqlite3.Error as e:
        logging.error(f"Failed to retrieve address for {username}: {str(e)}")
        return None

def get_user_port(username):
    """Retrieve the port for a user."""
    try:
        with sqlite3.connect('p2p.db') as conn:
            c = conn.cursor()
            c.execute('SELECT port FROM users WHERE username = ?', (username,))
            result = c.fetchone()
            if result:
                return result[0]
            logging.debug(f"No port found for {username}")
            return None
    except sqlite3.Error as e:
        logging.error(f"Failed to retrieve port for {username}: {str(e)}")
        return None