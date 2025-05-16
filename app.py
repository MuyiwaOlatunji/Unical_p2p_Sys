import hashlib
import socket
import asyncio
import logging
import os
import re
import secrets
import io
import mimetypes
from quart import Quart, request, render_template, redirect, url_for, flash, send_file, session, jsonify
from p2p_network import P2PNode
from database import init_db, register_user, verify_user, store_resource, get_resources, get_resource_key, store_message, get_messages, get_all_users, log_usage, get_user_address, get_user_port, get_user_private_key
from security import hash_password, generate_key_pair, decrypt_file
from werkzeug.utils import secure_filename
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

app = Quart(__name__)
app.secret_key = secrets.token_hex(16)
app.config['EXPLAIN_TEMPLATE_LOADING'] = False
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB
nodes = {}
private_keys = {}
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

init_db()

bootstrap_node = P2PNode("bootstrap", 8468)

def is_valid_email(email):
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None

def is_port_available(port):
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.bind(('0.0.0.0', port))
            return True
        except socket.error:
            return False

def find_available_port(start_port=9000, end_port=9999, exclude_ports=None):
    exclude_ports = exclude_ports or set()
    for port in range(start_port, end_port + 1):
        if port in exclude_ports:
            continue
        if is_port_available(port):
            return port
    raise Exception("No available ports in range")

def login_required(f):
    async def wrap(*args, **kwargs):
        if not session.get('username'):
            await flash('Please log in to access this page.')
            return redirect(url_for('login'))
        return await f(*args, **kwargs)
    wrap.__name__ = f.__name__
    return wrap

@app.before_serving
async def startup():
    try:
        await bootstrap_node.start()
        logging.info("Bootstrap node started on 127.0.0.1:8468")
    except Exception as e:
        logging.error(f"Failed to start bootstrap node: {str(e)}", exc_info=True)
        raise

@app.after_serving
async def shutdown():
    try:
        await bootstrap_node.stop()
        logging.info("Bootstrap node stopped")
    except Exception as e:
        logging.error(f"Failed to stop node for bootstrap: {str(e)}")
        raise

@app.route('/')
async def index():
    return await render_template('index.html')

@app.route('/favicon.ico')
async def favicon():
    favicon_path = os.path.join('static', 'favicon.ico')
    if os.path.exists(favicon_path):
        return await send_file(favicon_path)
    return '', 204

@app.route('/register', methods=['GET', 'POST'])
async def register():
    if request.method == 'POST':
        form = await request.form
        email = form.get('email', '').strip()
        password = form.get('password', '').strip()
        if not email or not password:
            await flash('Email and password are required.')
            return await render_template('register.html'), 400
        if not is_valid_email(email):
            await flash('Please enter a valid email address.')
            return await render_template('register.html'), 400
        if email in nodes:
            await flash('User is already active. Please log in.')
            return await render_template('register.html'), 400
        try:
            used_ports = {node.port for node in nodes.values()}
            port = find_available_port(exclude_ports=used_ports)
        except Exception as e:
            await flash(str(e))
            return await render_template('register.html'), 500
        node_id = secrets.token_hex(16)
        peer_id = secrets.token_hex(16)
        try:
            private_key, public_key = generate_key_pair()
            public_key_pem = public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode('ascii')
            private_key_pem = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ).decode('ascii')
        except Exception as e:
            logging.error(f"Key pair generation failed: {str(e)}")
            await flash(f"Error generating key pair: {str(e)}")
            return await render_template('register.html'), 500
        node = P2PNode(email, port, bootstrap_nodes=[('127.0.0.1', 8468)])
        try:
            logging.debug(f"Starting node for {email} on port {port}")
            address = await node.start()
            logging.debug(f"Node started at {address}, node_id: {node_id}, peer_id: {peer_id}")
            if register_user(email, hash_password(password), node_id, public_key_pem, address, peer_id, port, private_key_pem):
                nodes[email] = node
                private_keys[email] = private_key
                log_usage(email, 'register')
                await flash('Registration successful! Please log in.')
                return redirect(url_for('login'))
            else:
                await node.stop()
                await flash('Email already registered.')
                return await render_template('register.html'), 400
        except Exception as e:
            logging.error(f"Registration failed for {email} on port {port}: {str(e)}", exc_info=True)
            await flash(f"Registration failed. Please try again later.")
            await node.stop()
            return await render_template('register.html'), 500
    return await render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
async def login():
    if request.method == 'POST':
        form = await request.form
        email = form.get('email', '').strip()
        password = form.get('password', '').strip()
        logging.debug(f"Login form data: {dict(form)}")
        if not email or not password:
            await flash('Email and password are required.')
            return await render_template('login.html'), 400
        if not is_valid_email(email):
            await flash('Please enter a valid email address.')
            return await render_template('login.html'), 400
        if verify_user(email, hash_password(password)):
            if email in nodes:
                session['username'] = email
                log_usage(email, 'login')
                await flash(f'Welcome, {email}!')
                return redirect(url_for('dashboard', username=email))
            port = get_user_port(email)
            used_ports = {node.port for node in nodes.values()}
            if port and port not in used_ports and is_port_available(port):
                pass
            else:
                try:
                    port = find_available_port(exclude_ports=used_ports)
                except Exception as e:
                    await flash(str(e))
                    return await render_template('login.html'), 500
            node = P2PNode(email, port, bootstrap_nodes=[('127.0.0.1', 8468)])
            try:
                logging.debug(f"Starting node for {email} on port {port}")
                address = await node.start()
                logging.debug(f"Node started at {address}")
                nodes[email] = node
                private_key_pem = get_user_private_key(email)
                if private_key_pem:
                    private_key = serialization.load_pem_private_key(
                        private_key_pem.encode('ascii'),
                        password=None,
                        backend=default_backend()
                    )
                    private_keys[email] = private_key
                else:
                    logging.warning(f"No private key found in database for {email}")
                session['username'] = email
                log_usage(email, 'login')
                await flash(f'Welcome, {email}!')
                return redirect(url_for('dashboard', username=email))
            except Exception as e:
                logging.error(f"Login failed for {email} on port {port}: {str(e)}", exc_info=True)
                await flash(f"Login failed. Please try again later.")
                await node.stop()
                return await render_template('login.html'), 500
        else:
            await flash('Invalid credentials.')
            return await render_template('login.html'), 401
    return await render_template('login.html')

@app.route('/logout')
async def logout():
    username = session.get('username')
    if username and username in nodes:
        try:
            await nodes[username].stop()
            logging.debug(f"Node stopped for {username}")
        except Exception as e:
            logging.error(f"Failed to stop node for {username}: {str(e)}")
        del nodes[username]
        if username in private_keys:
            del private_keys[username]
    session.pop('username', None)
    await flash('Logged out successfully.')
    return redirect(url_for('index'))

@app.route('/dashboard/<username>')
@login_required
async def dashboard(username):
    if username != session.get('username'):
        await flash('Unauthorized access.')
        return redirect(url_for('login'))
    category = request.args.get('category', '')
    search = request.args.get('search', '')
    resources = get_resources(category, search)
    categories = ['Documents', 'Images', 'Audio', 'Video']
    return await render_template('dashboard.html', username=username, resources=resources, categories=categories, selected_category=category, search=search)

@app.route('/upload', methods=['POST'])
@login_required
async def upload():
    form = await request.form
    files = await request.files
    username = form.get('username', '').strip()
    if username != session.get('username'):
        await flash('Unauthorized upload attempt.')
        return redirect(url_for('login'))
    file = files.get('file')
    category = form.get('category', '').strip()
    if not file or not category or category not in ['Documents', 'Images', 'Audio', 'Video']:
        await flash('Invalid file or category.')
        return redirect(url_for('dashboard', username=username))
    node = nodes.get(username)
    if not node:
        await flash('Error uploading file: Node not found.')
        return redirect(url_for('dashboard', username=username))
    filename = secure_filename(file.filename)
    try:
        file_data = file.read()
        if not file_data:
            await flash('File is empty.')
            return redirect(url_for('dashboard', username=username))
        file_hash = await node.share_file(filename, file_data, category)
        store_resource(filename, category, file_hash, username, node.files[filename][2], None)
        await flash('File uploaded successfully.')
    except Exception as e:
        logging.error(f"Upload failed for {filename}: {str(e)}")
        if "413" in str(e) or "Request Entity Too Large" in str(e):
            await flash('File too large. Maximum size is 16MB.')
        else:
            await flash(f"Error uploading file: {str(e)}")
        return redirect(url_for('dashboard', username=username))
    return redirect(url_for('dashboard', username=username))

@app.route('/download/<filename>', methods=['GET'])
@login_required
async def download(filename):
    username = request.args.get('username')
    if username != session.get('username'):
        await flash('Unauthorized download attempt.')
        return redirect(url_for('login'))
    node = nodes.get(username)
    if not node:
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
            logging.error(f"Failed to retrieve {filename} from node")
            await flash('File not found or inaccessible.')
            return redirect(url_for('dashboard', username=username))
        
        if retrieved_hash != file_hash:
            logging.error(f"Hash mismatch for {filename}: expected {file_hash}, got {retrieved_hash}")
            await flash('File integrity check failed.')
            return redirect(url_for('dashboard', username=username))
        
        decrypted_data = decrypt_file(encrypted_data, aes_key)
        logging.debug(f"Successfully decrypted {filename}")
        
        mime_type, _ = mimetypes.guess_type(filename)
        if not mime_type:
            mime_type = 'application/octet-stream'
        
        # Add Content-Disposition header to force download
        response = await send_file(
            io.BytesIO(decrypted_data),
            download_name=filename,
            as_attachment=True,
            mimetype=mime_type
        )
        response.headers['Content-Disposition'] = f'attachment; filename="{filename}"'
        return response
    except Exception as e:
        logging.error(f"Error downloading file {filename}: {str(e)}", exc_info=True)
        await flash(f'Error downloading file: {str(e)}')
        return redirect(url_for('dashboard', username=username))

@app.route('/messages/<username>')
@login_required
async def messages(username):
    if username != session.get('username'):
        await flash('Unauthorized access.')
        return redirect(url_for('login'))
    messages = get_messages(username)
    users = get_all_users()
    return await render_template('messages.html', username=username, messages=messages, users=users)

@app.route('/send_message', methods=['POST'])
@login_required
async def send_message_route():
    form = await request.form
    username = form.get('username', '').strip()
    if username != session.get('username'):
        await flash('Unauthorized message attempt.')
        return redirect(url_for('login'))
    recipient = form.get('recipient', '').strip()
    content = form.get('message', '').strip()
    if not content:
        await flash('Message cannot be empty.')
        return redirect(url_for('messages', username=username))
    store_message(username, recipient, content)
    await flash('Message sent!')
    return redirect(url_for('messages', username=username))

@app.route('/check_messages/<username>', methods=['GET'])
@login_required
async def check_messages(username):
    if username != session.get('username'):
        return jsonify({'error': 'Unauthorized'}), 403
    messages = get_messages(username)
    return jsonify([{
        'sender': msg[0],
        'recipient': msg[1],
        'content': msg[2],
        'timestamp': msg[3]
    } for msg in messages])

if __name__ == '__main__':
    import uvicorn
    uvicorn.run(app, host='0.0.0.0', port=5000, log_level='debug')