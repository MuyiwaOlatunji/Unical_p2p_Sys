import hashlib
import socket
import asyncio
import logging
import os
import re
import secrets
import io
import mimetypes
import datetime
import uuid
import json
from quart import Quart, request, render_template, redirect, url_for, flash, Response, session
from p2p_network import P2PNode
from database import init_db, register_user, verify_user, store_resource, get_resources, get_resource_key, store_message, get_messages, get_all_users, log_usage, get_user_address, get_user_port, get_user_private_key, get_used_ports, get_db_connection
from security import hash_password, verify_password, generate_key_pair, decrypt_file, encrypt_file
from werkzeug.utils import secure_filename
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from urllib.parse import quote

# Initialize logging and app
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')
app = Quart(__name__)
app.secret_key = secrets.token_hex(16)
app.config['EXPLAIN_TEMPLATE_LOADING'] = False
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB
nodes = {}
private_keys = {}
mimetypes.init()
init_db()

# Debug import
logging.debug(f"encrypt_file imported: {encrypt_file}")

# Debug routes at startup
@app.before_serving
async def log_routes():
    routes = [rule.endpoint for rule in app.url_map.iter_rules()]
    logging.info(f"Registered routes: {routes}")

async def find_available_port(start_port=9001, end_port=9999):
    used_ports = get_used_ports()
    for port in range(start_port, end_port + 1):
        if port in used_ports:
            continue
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.bind(('0.0.0.0', port))
            sock.close()
            return port
        except OSError:
            continue
    raise RuntimeError("No available ports found in range")

def is_port_available(port):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        try:
            sock.bind(('0.0.0.0', port))
            return True
        except OSError:
            return False

def find_bootstrap_port(start_port=8468, end_port=8499):
    for port in range(start_port, end_port + 1):
        if is_port_available(port):
            return port
    raise Exception(f"No available ports for bootstrap node in range {start_port}-{end_port}")

# Initialize bootstrap node
try:
    bootstrap_port = find_bootstrap_port()
    bootstrap_node = P2PNode("bootstrap", port=bootstrap_port)
    logging.info(f"Bootstrap node initialized on port {bootstrap_port}")
except Exception as e:
    logging.error(f"Failed to initialize bootstrap node: {str(e)}")
    raise

@app.before_serving
async def startup():
    try:
        await bootstrap_node.start()
        logging.info(f"Bootstrap node started on 127.0.0.1:{bootstrap_node.port}")
    except Exception as e:
        logging.error(f"Failed to start bootstrap node: {str(e)}", exc_info=True)
        raise

@app.after_serving
async def shutdown():
    try:
        await bootstrap_node.stop()
        logging.info("Bootstrap node stopped")
    except Exception as e:
        logging.error(f"Failed to stop bootstrap node: {str(e)}")
        raise

def login_required(f):
    async def wrapper(*args, **kwargs):
        if 'username' not in session:
            await flash('Please log in to access this page.')
            return redirect(url_for('login'))
        return await f(*args, **kwargs)
    wrapper.__name__ = f.__name__
    return wrapper

@app.route('/')
async def index():
    if 'username' in session:
        return redirect(url_for('dashboard', username=session['username']))
    return redirect(url_for('login'))

@app.route('/favicon.ico')
async def favicon():
    favicon_path = os.path.join('static', 'favicon.ico')
    if os.path.exists(favicon_path):
        with open(favicon_path, 'rb') as f:
            return await Response(f.read(), mimetype='image/x-icon')
    logging.debug("No favicon found, returning 204")
    return Response(status=204)

@app.route('/register', methods=['GET', 'POST'])
async def register():
    if request.method == 'POST':
        form = await request.form
        email = form.get('email', '').strip()
        password = form.get('password', '')
        if not email or not password:
            await flash('Email and password are required.')
            return await render_template('register.html')
        if len(password) < 8:
            await flash('Password must be at least 8 characters long.')
            return await render_template('register.html')
        if not re.match(r'^[\w\.-]+@[\w\.-]+\.\w+$', email):
            await flash('Invalid email format.')
            return await render_template('register.html')
        
        try:
            port = await find_available_port()
            public_key, private_key = generate_key_pair()
            hashed_password = hash_password(password)
            public_key_pem = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode('utf-8')
            private_key_pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ).decode('utf-8')
            register_user(email, hashed_password, '127.0.0.1', port, public_key_pem, private_key_pem)
            logging.debug(f"User {email} registered with port {port}")
            await flash('Registration successful. Please log in.')
            return redirect(url_for('login'))
        except ValueError as e:
            logging.error(f"Registration failed for {email}: {str(e)}")
            await flash(str(e))
            return await render_template('register.html')
        except Exception as e:
            logging.error(f"Registration failed for {email}: {str(e)}")
            await flash(f'Registration failed: {str(e)}')
            return await render_template('register.html')
    return await render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
async def login():
    if request.method == 'POST':
        form = await request.form
        email = form.get('email', '').strip()
        password = form.get('password', '')
        logging.debug(f"Login form data: {{'email': '{email}', 'password': '[REDACTED]'}}")
        
        user = verify_user(email, password)
        if user:
            session['username'] = email
            try:
                address = get_user_address(email)
                port = get_user_port(email)
                private_key_pem = get_user_private_key(email)
                private_key = serialization.load_pem_private_key(
                    private_key_pem.encode('utf-8'),
                    password=None,
                    backend=default_backend()
                )
                node = P2PNode(email, port=port, address=address)
                logging.debug(f"Starting node for {email} on port {port}")
                await node.start()
                nodes[email] = node
                private_keys[email] = private_key
                logging.debug(f"Node started at {address}:{port}")
                log_usage(email, 'login', datetime.datetime.now())
                return redirect(url_for('dashboard', username=email))
            except Exception as e:
                logging.error(f"Failed to start node for {email} on port {port}: {str(e)}", exc_info=True)
                await flash(f'Failed to start node: {str(e)}')
                return await render_template('login.html')
        else:
            conn = get_db_connection()
            cursor = conn.cursor()
            cursor.execute('SELECT email FROM users WHERE email = ?', (email,))
            user_exists = cursor.fetchone()
            conn.close()
            if user_exists:
                await flash('Incorrect password.')
            else:
                await flash('Email not registered.')
            logging.debug(f"Verification failed for {email}")
            return await render_template('login.html')
    return await render_template('login.html')

@app.route('/dashboard/<username>')
@login_required
async def dashboard(username):
    if username != session.get('username'):
        await flash('Unauthorized access.')
        return redirect(url_for('login'))
    resources = get_resources()
    messages = get_messages(username)
    users = get_all_users()
    return await render_template('dashboard.html', username=username, resources=resources, messages=messages, users=users, categories=['Documents', 'Images', 'Videos', 'Other'], selected_category='', search='')

@app.route('/upload', methods=['POST'])
@login_required
async def upload():
    username = session.get('username')
    form = await request.form
    files = await request.files
    file = files.get('file')
    category = form.get('category', 'Other')
    
    if not file:
        await flash('No file selected.')
        return redirect(url_for('dashboard', username=username))
    
    filename = secure_filename(file.filename)
    try:
        file_data = file.read()
        file_hash = hashlib.sha256(file_data).hexdigest()
        node = nodes.get(username)
        if not node:
            await flash('User node not found.')
            return redirect(url_for('dashboard', username=username))
        
        aes_key = os.urandom(32)
        logging.debug(f"Calling encrypt_file with data length {len(file_data)} and aes_key length {len(aes_key)}")
        encrypted_data = encrypt_file(file_data, aes_key)
        save_path = os.path.join('Uploads', filename)
        os.makedirs(os.path.dirname(save_path), exist_ok=True)
        with open(save_path, 'wb') as f:
            f.write(encrypted_data)
        logging.debug(f"Saved encrypted file {filename} to {save_path}")
        
        await node.share_file(filename, category, aes_key, save_path)
        store_resource(filename, category, file_hash, username)
        logging.debug(f"Resource {filename} stored for {username}")
        await flash('File uploaded successfully.')
    except Exception as e:
        logging.error(f"Error uploading file {filename}: {str(e)}", exc_info=True)
        await flash(f'Error uploading file: {str(e)}')
    return redirect(url_for('dashboard', username=username))

@app.route('/messages/<username>', methods=['GET'])
@login_required
async def messages(username):
    if username != session.get('username'):
        await flash('Unauthorized access.')
        return redirect(url_for('login'))
    messages = get_messages(username)
    users = get_all_users()
    return await render_template('messages.html', username=username, messages=messages, users=users)

@app.route('/download/<filename>', methods=['GET'])
@login_required
async def download(filename):
    username = request.args.get('username')
    logging.debug(f"Download request for {filename} by {username}")
    if username != session.get('username'):
        logging.warning(f"Unauthorized download attempt by {username}")
        await flash('Unauthorized download attempt.')
        return redirect(url_for('login'))
    node = nodes.get(username)
    if not node:
        logging.error(f"User node not found for {username}")
        await flash('User node not found.')
        return redirect(url_for('dashboard', username=username))
    
    file_hash = None
    for resource in get_resources():
        if resource[0] == filename:
            file_hash = resource[2]
            break
    if not file_hash:
        logging.error(f"File hash not found for {filename}")
        await flash('File hash not found.')
        return redirect(url_for('dashboard', username=username))
    
    private_key = private_keys.get(username)
    if not private_key:
        logging.error(f"No private key for {username}")
        await flash('Private key not found.')
        return redirect(url_for('dashboard', username=username))
    
    try:
        encrypted_data, aes_key, retrieved_hash = await node.request_file(None, filename, private_key, file_hash=file_hash)
        if not encrypted_data or not aes_key or not retrieved_hash:
            logging.error(f"Failed to retrieve {filename} from node: {encrypted_data=}, {aes_key=}, {retrieved_hash=}")
            await flash('File not found or inaccessible.')
            return redirect(url_for('dashboard', username=username))
        
        if retrieved_hash != file_hash:
            logging.error(f"Hash mismatch for {filename}: expected {file_hash}, got {retrieved_hash}")
            await flash('File integrity check failed.')
        logging.debug(f"Decrypting {filename} with aes_key length {len(aes_key)}")
        decrypted_data = decrypt_file(encrypted_data, aes_key)
        logging.debug(f"Successfully decrypted {filename}, size: {len(decrypted_data)} bytes")
        
        mime_type, _ = mimetypes.guess_type(filename)
        if not mime_type:
            extension = os.path.splitext(filename)[1].lower()
            mime_types = {
                '.mp3': 'audio/mpeg',
                '.wav': 'audio/wav',
                '.ogg': 'audio/ogg',
                '.mp4': 'video/mp4',
                '.pdf': 'application/pdf',
                '.jpg': 'image/jpeg',
                '.jpeg': 'image/jpeg',
                '.png': 'image/png',
                '.docx': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
                '.txt': 'text/plain',
                '.zip': 'application/zip'
            }
            mime_type = mime_types.get(extension, 'application/octet-stream')
        
        logging.debug(f"Sending file {filename} with MIME type {mime_type}")
        
        encoded_filename = quote(secure_filename(filename))
        headers = {
            'Content-Type': mime_type,
            'Content-Disposition': f'attachment; filename="{encoded_filename}"; filename*=UTF-8''{encoded_filename}',
            'Content-Length': str(len(decrypted_data)),
            'Cache-Control': 'no-cache, no-store, must-revalidate',
            'Pragma': 'no-cache',
            'Expires': '0'
        }
        
        return Response(
            decrypted_data,
            status=200,
            headers=headers
        )
    except Exception as e:
        logging.error(f"Error downloading file {filename}: {str(e)}", exc_info=True)
        await flash(f'Error downloading file: {str(e)}')
        return redirect(url_for('dashboard', username=username))

@app.route('/message', methods=['POST'])
@login_required
async def message():
    username = session.get('username')
    form = await request.form
    recipient = form.get('recipient')
    content = form.get('message')
    
    try:
        store_message(username, recipient, content)
        await flash('Message sent successfully.')
    except Exception as e:
        logging.error(f"Error sending message from {username} to {recipient}: {str(e)}")
        await flash(f'Error sending message: {str(e)}')
    return redirect(url_for('dashboard', username=username))

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)