#!/usr/bin/env python3
"""
Flask Web Application for Fractured Keys
A modern web interface for the steganographic password manager
"""

import os
import io
import base64
import tempfile
from flask import Flask, render_template, request, jsonify, send_file
from werkzeug.utils import secure_filename
from PIL import Image

# Import existing modules
from encryption import encryption_mode_web
from decryption import decryption_mode_web, decryption_mode_manual_web
from colors import Colors

app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24)
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

# Allowed image extensions
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'bmp', 'tiff'}

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/')
def index():
    """Main page with encryption/decryption options"""
    return render_template('index.html')

@app.route('/encrypt', methods=['GET', 'POST'])
def encrypt():
    """Handle password encryption and steganography"""
    if request.method == 'GET':
        return render_template('encrypt.html')
    
    try:
        # Get form data
        password = request.form.get('password', '').strip()
        master_password = request.form.get('master_password', '').strip()
        threshold = int(request.form.get('threshold', 2))
        total_shares = int(request.form.get('total_shares', 3))
        
        if not password or not master_password:
            return jsonify({'error': 'Password and master password are required'}), 400
        
        if threshold > total_shares:
            return jsonify({'error': 'Threshold cannot be greater than total shares'}), 400
        
        # Get uploaded images
        uploaded_files = request.files.getlist('images')
        if len(uploaded_files) < total_shares:
            return jsonify({'error': f'Please upload at least {total_shares} images'}), 400
        
        # Validate uploaded files
        images = []
        for file in uploaded_files[:total_shares]:
            if file and allowed_file(file.filename):
                images.append(file)
            else:
                return jsonify({'error': 'Invalid image file format'}), 400
        
        # Process encryption
        result = encryption_mode_web(password, master_password, threshold, total_shares, images)
        
        if result['success']:
            return jsonify({
                'success': True,
                'message': 'Encryption completed successfully!',
                'images': result['images']
            })
        else:
            return jsonify({'error': result['error']}), 500
            
    except Exception as e:
        return jsonify({'error': f'Encryption failed: {str(e)}'}), 500

@app.route('/decrypt', methods=['GET', 'POST'])
def decrypt():
    """Handle password decryption from steganographic images"""
    if request.method == 'GET':
        return render_template('decrypt.html')
    
    try:
        master_password = request.form.get('master_password', '').strip()
        if not master_password:
            return jsonify({'error': 'Master password is required'}), 400
        
        # Get uploaded images
        uploaded_files = request.files.getlist('stego_images')
        if not uploaded_files:
            return jsonify({'error': 'Please upload at least one steganographic image'}), 400
        
        # Validate uploaded files
        images = []
        for file in uploaded_files:
            if file and allowed_file(file.filename):
                images.append(file)
            else:
                return jsonify({'error': 'Invalid image file format'}), 400
        
        # Process decryption
        result = decryption_mode_web(master_password, images)
        
        if result['success']:
            return jsonify({
                'success': True,
                'password': result['password'],
                'message': 'Decryption completed successfully!'
            })
        else:
            return jsonify({'error': result['error']}), 500
            
    except Exception as e:
        return jsonify({'error': f'Decryption failed: {str(e)}'}), 500

@app.route('/manual_decrypt', methods=['GET', 'POST'])
def manual_decrypt():
    """Handle manual decryption from binary files or base64"""
    if request.method == 'GET':
        return render_template('manual_decrypt.html')
    
    try:
        master_password = request.form.get('master_password', '').strip()
        decrypt_type = request.form.get('decrypt_type', 'file')
        
        if not master_password:
            return jsonify({'error': 'Master password is required'}), 400
        
        if decrypt_type == 'file':
            # Handle file upload
            uploaded_file = request.files.get('binary_file')
            if not uploaded_file:
                return jsonify({'error': 'Please upload a binary file'}), 400
            
            result = decryption_mode_manual_web(master_password, file_data=uploaded_file.read())
        else:
            # Handle base64 input
            base64_data = request.form.get('base64_data', '').strip()
            if not base64_data:
                return jsonify({'error': 'Please provide base64 data'}), 400
            
            result = decryption_mode_manual_web(master_password, base64_data=base64_data)
        
        if result['success']:
            return jsonify({
                'success': True,
                'password': result['password'],
                'message': 'Manual decryption completed successfully!'
            })
        else:
            return jsonify({'error': result['error']}), 500
            
    except Exception as e:
        return jsonify({'error': f'Manual decryption failed: {str(e)}'}), 500

@app.route('/download/<filename>')
def download_file(filename):
    """Download generated steganographic images"""
    try:
        # This would be implemented to serve generated files
        # For now, return a placeholder
        return jsonify({'error': 'Download functionality not implemented yet'}), 501
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    # Create templates and static directories if they don't exist
    os.makedirs('templates', exist_ok=True)
    os.makedirs('static/css', exist_ok=True)
    os.makedirs('static/js', exist_ok=True)
    os.makedirs('static/images', exist_ok=True)
    
    print("Starting Fractured Keys Web Interface...")
    print("Access the application at: http://localhost:5000")
    app.run(debug=True, host='0.0.0.0', port=5000)
