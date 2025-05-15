from quart import Quart, request, render_template, redirect, url_for, flash, send_file, session, jsonify
from p2p_network import P2PNode
from database import init_db, register_user, verify_user, store_resource, get_resources, get_resource_key, store_message, get_messages, get_all_users, log_usage, get_user_address
from security import hash_password, generate_key_pair, decrypt_file
import secrets
import io
import os
import logging
from werkzeug.utils import secure_filename

app = Quart(__name__)
app.secret_key = secrets.token_hex(16)
app.config['EXPLAIN_TEMPLATE_LOADING'] = False
nodes = {}
private_keys = {}
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

init_db()

def login_required(f):
    async def wrap(*args, **kwargs):
        if not session.get('username'):
            await flash('Please log in to access this page.')
            return redirect(url_for('login'))
        return await f(*args, **kwargs)
    wrap.__name__ = f.__name__
    return wrap

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
        username = secure_filename(form['username']).strip()
        password = form['password']
        port = int(form['port'])
        if not (username and password and port >= 1024):
            await flash('Invalid input. Username, password, and port (≥1024) are required.')
            return await render_template('register.html')
        node_id = secrets.token_hex(16)
        peer_id = secrets.token_hex(16)  # Generate peer_id
        try:
            private_key, public_key = generate_key_pair()
        except Exception as e:
            logging.error(f"Key pair generation failed: {str(e)}")
            await flash(f"Error generating key pair: {str(e)}")
            return await render_template('register.html')
        node = P2PNode(username, port)
        try:
            logging.debug(f"Starting node for {username} on port {port}")
            address = await node.start()
            logging.debug(f"Node started at {address}, node_id: {node_id}, peer_id: {peer_id}")
            if register_user(username, hash_password(password), node_id, public_key, address, peer_id):
                nodes[username] = node
                private_keys[username] = private_key
                log_usage(username, 'register')
                await flash('Registration successful! Please log in.')
                return redirect(url_for('login'))
            else:
                await node.stop()
                await flash('Username already exists.')
        except Exception as e:
            logging.error(f"Registration failed for {username} on port {port}: {str(e)}", exc_info=True)
            await flash(f"Error: {str(e)}")
            await node.stop()
    return await render_template('register.html')

@app.route('/login', methods=['GET', 'POST'])
async def login():
    if request.method == 'POST':
        form = await request.form
        username = secure_filename(form['username']).strip()
        password = form['password']
        port = int(form['port'])
        if verify_user(username, hash_password(password)):
            node = P2PNode(username, port)
            try:
                logging.debug(f"Starting node for {username} on port {port}")
                address = await node.start()
                logging.debug(f"Node started at {address}")
                nodes[username] = node
                session['username'] = username
                log_usage(username, 'login')
                await flash(f'Welcome, {username}!')
                return redirect(url_for('dashboard', username=username))
            except Exception as e:
                logging.error(f"Login failed for {username} on port {port}: {str(e)}", exc_info=True)
                await flash(f"Error: {str(e)}")
                await node.stop()
        else:
            await flash('Invalid credentials.')
    return await render_template('login.html')

@app.route('/logout')
async def logout():
    username = session.get('username')
    if username and username in nodes:
        await nodes[username].stop()
        del nodes[username]
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
    username = form['username']
    if username != session.get('username'):
        await flash('Unauthorized upload attempt.')
        return redirect(url_for('login'))
    file = files['file']
    category = form['category']
    if file and category in ['Documents', 'Images', 'Audio', 'Video']:
        node = nodes.get(username)
        if node:
            filename = secure_filename(file.filename)
            file_data = await file.read()
            if not file_data:
                await flash('File is empty.')
                return redirect(url_for('dashboard', username=username))
            try:
                file_hash = await node.share_file(filename, file_data, category)
                os.makedirs('Uploads', exist_ok=True)
                upload_path = os.path.join('Uploads', filename)
                with open(upload_path, 'wb') as f:
                    f.write(file_data)
                store_resource(filename, category, file_hash, username, node.files[filename][2], None)  # cid=None
                await flash('File uploaded successfully.')
            except Exception as e:
                logging.error(f"Upload failed for {filename}: {str(e)}")
                await flash(f"Error uploading file: {str(e)}")
        else:
            await flash('Error uploading file: Node not found.')
    else:
        await flash('Invalid file or category.')
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
    
    aes_key, owner, cid = get_resource_key(filename)
    if not aes_key or not owner:
        logging.error(f"Resource key not found for {filename}")
        await flash('File not found or corrupted.')
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
    
    encrypted_data = None
    try:
        encrypted_data = await node.server.get(file_hash)
        logging.debug(f"Retrieved {filename} from DHT with hash {file_hash}")
    except Exception as e:
        logging.error(f"Failed to retrieve {filename} from DHT: {str(e)}")
    
    if not encrypted_data:
        try:
            upload_path = os.path.join('Uploads', filename)
            with open(upload_path, 'rb') as f:
                encrypted_data = f.read()
            logging.debug(f"Retrieved {filename} from Uploads directory")
        except FileNotFoundError:
            logging.error(f"File {filename} not found in Uploads")
            await flash('File not found.')
            return redirect(url_for('dashboard', username=username))
    
    try:
        decrypted_data = decrypt_file(encrypted_data, aes_key)
        logging.debug(f"Successfully decrypted {filename}")
        return await send_file(
            io.BytesIO(decrypted_data),
            download_name=filename,
            as_attachment=True,
            mimetype='application/octet-stream'
        )
    except Exception as e:
        logging.error(f"Error decrypting file {filename}: {str(e)}")
        await flash(f'Error decrypting file: {str(e)}')
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
    username = form['username']
    if username != session.get('username'):
        await flash('Unauthorized message attempt.')
        return redirect(url_for('login'))
    recipient = form['recipient']
    content = form['message'].strip()
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