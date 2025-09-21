#!/usr/bin/env python3
"""
Fractured Keys - Simple Reliable GUI
A secure password manager using Shamir Secret Sharing and steganography
"""

import tkinter as tk
from tkinter import ttk, messagebox, filedialog, scrolledtext
import threading
import os
import sys

# Add current directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from steganography import embed_data_into_image, extract_data_from_image
from sss import split_bytes_into_shares, recover_bytes_from_shares
from crypto import encrypt_password_aes_gcm, decrypt_password_aes_gcm

class SimpleFracturedKeysGUI:
    def __init__(self, root):
        self.root = root
        self.setup_window()
        self.create_widgets()
        
    def setup_window(self):
        """Configure the main window"""
        self.root.title("🔐 Fractured Keys - Secure Password Manager")
        self.root.geometry("900x700")
        self.root.configure(bg='#f8f9fa')
        
        # Center the window
        self.root.update_idletasks()
        x = (self.root.winfo_screenwidth() // 2) - (900 // 2)
        y = (self.root.winfo_screenheight() // 2) - (700 // 2)
        self.root.geometry(f"900x700+{x}+{y}")
        
        # Configure custom styles
        self.setup_styles()
        
    def setup_styles(self):
        """Setup custom styles and colors"""
        # Define color scheme
        self.colors = {
            'primary': '#2c3e50',
            'secondary': '#34495e', 
            'accent': '#3498db',
            'success': '#27ae60',
            'warning': '#f39c12',
            'error': '#e74c3c',
            'background': '#f8f9fa',
            'surface': '#ffffff',
            'text': '#2c3e50',
            'text_light': '#7f8c8d',
            'border': '#dee2e6',
            'hover': '#e9ecef'
        }
        
        # Configure ttk styles
        style = ttk.Style()
        style.theme_use('clam')
        
        # Configure notebook style
        style.configure('TNotebook', background=self.colors['background'])
        style.configure('TNotebook.Tab', 
                       background=self.colors['surface'],
                       foreground=self.colors['text'],
                       padding=[20, 10],
                       font=('Arial', 11, 'bold'))
        style.map('TNotebook.Tab',
                 background=[('selected', self.colors['accent']),
                           ('active', self.colors['hover'])],
                 foreground=[('selected', 'white'),
                           ('active', self.colors['text'])])
        
        # Configure progress bar style
        style.configure('Custom.Horizontal.TProgressbar',
                       background=self.colors['accent'],
                       troughcolor=self.colors['border'],
                       borderwidth=0,
                       lightcolor=self.colors['accent'],
                       darkcolor=self.colors['accent'])
        
    def create_widgets(self):
        """Create all GUI widgets"""
        # Header frame with gradient-like effect
        header_frame = tk.Frame(self.root, bg=self.colors['primary'], height=120)
        header_frame.pack(fill='x', pady=(0, 20))
        header_frame.pack_propagate(False)
        
        # Main title with better styling
        title_label = tk.Label(header_frame, text="🔐 Fractured Keys", 
                              font=('Arial', 24, 'bold'), 
                              bg=self.colors['primary'], fg='white')
        title_label.pack(pady=(20, 5))
        
        subtitle_label = tk.Label(header_frame, text="Offline Password Manager with Steganography", 
                                 font=('Arial', 13), 
                                 bg=self.colors['primary'], fg='#bdc3c7')
        subtitle_label.pack(pady=(0, 20))
        
        # Create notebook for tabs with better styling
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill='both', expand=True, padx=30, pady=(0, 20))
        
        # Create tabs
        self.create_encrypt_tab()
        self.create_decrypt_tab()
        self.create_manual_tab()
        self.create_about_tab()
        
        # Enhanced status bar
        status_frame = tk.Frame(self.root, bg=self.colors['secondary'], height=30)
        status_frame.pack(side=tk.BOTTOM, fill=tk.X)
        status_frame.pack_propagate(False)
        
        self.status_var = tk.StringVar()
        self.status_var.set("Ready")
        status_bar = tk.Label(status_frame, textvariable=self.status_var, 
                             anchor=tk.W, 
                             bg=self.colors['secondary'], fg='white',
                             font=('Arial', 10))
        status_bar.pack(side=tk.LEFT, padx=15, pady=5)
        
    def create_encrypt_tab(self):
        """Create encryption tab"""
        self.encrypt_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.encrypt_frame, text="🔒 Encrypt")
        
        # Create main content frame with padding
        main_frame = tk.Frame(self.encrypt_frame, bg=self.colors['surface'])
        main_frame.pack(fill='both', expand=True, padx=25, pady=25)
        
        # Password input section
        input_frame = tk.Frame(main_frame, bg=self.colors['surface'])
        input_frame.pack(fill='x', pady=(0, 20))
        
        tk.Label(input_frame, text="Password to Encrypt:", 
                font=('Arial', 13, 'bold'), 
                bg=self.colors['surface'], fg=self.colors['text']).pack(anchor='w', pady=(0, 8))
        
        self.password_entry = tk.Entry(input_frame, show="*", width=60, font=('Arial', 11),
                                     relief='solid', bd=1, highlightthickness=2,
                                     highlightcolor=self.colors['accent'])
        self.password_entry.pack(fill='x', pady=(0, 20))
        
        # Master password input
        tk.Label(input_frame, text="Master Password:", 
                font=('Arial', 13, 'bold'),
                bg=self.colors['surface'], fg=self.colors['text']).pack(anchor='w', pady=(0, 8))
        
        self.master_password_entry = tk.Entry(input_frame, show="*", width=60, font=('Arial', 11),
                                            relief='solid', bd=1, highlightthickness=2,
                                            highlightcolor=self.colors['accent'])
        self.master_password_entry.pack(fill='x', pady=(0, 20))
        
        # Options section
        options_frame = tk.Frame(main_frame, bg=self.colors['surface'])
        options_frame.pack(fill='x', pady=(0, 25))
        
        self.use_shares_var = tk.BooleanVar(value=True)
        shares_check = tk.Checkbutton(options_frame, 
                                     text="Split into 3 shares and embed into images", 
                                     variable=self.use_shares_var,
                                     font=('Arial', 11),
                                     bg=self.colors['surface'], fg=self.colors['text'],
                                     selectcolor=self.colors['accent'],
                                     activebackground=self.colors['surface'])
        shares_check.pack(anchor='w', pady=(0, 8))
        
        tk.Label(options_frame, text="(This will create 3 stego images. You need at least 2 to decrypt.)", 
                font=('Arial', 10), fg=self.colors['text_light'],
                bg=self.colors['surface']).pack(anchor='w', padx=20, pady=(0, 15))
        
        # Button section
        button_frame = tk.Frame(main_frame, bg=self.colors['surface'])
        button_frame.pack(fill='x', pady=(0, 20))
        
        self.encrypt_btn = tk.Button(button_frame, text="🔒 Start Encryption", 
                                    command=self.start_encryption,
                                    bg=self.colors['accent'], fg='white', 
                                    font=('Arial', 13, 'bold'),
                                    padx=30, pady=12, relief='flat',
                                    activebackground='#2980b9', activeforeground='white',
                                    cursor='hand2')
        self.encrypt_btn.pack(pady=(0, 15))
        
        # Progress bar with custom styling
        self.encrypt_progress = ttk.Progressbar(button_frame, mode='indeterminate',
                                              style='Custom.Horizontal.TProgressbar')
        self.encrypt_progress.pack(fill='x', pady=(0, 15))
        
        # Output area with better styling
        output_frame = tk.Frame(main_frame, bg=self.colors['surface'])
        output_frame.pack(fill='both', expand=True)
        
        tk.Label(output_frame, text="Output:", 
                font=('Arial', 13, 'bold'),
                bg=self.colors['surface'], fg=self.colors['text']).pack(anchor='w', pady=(0, 8))
        
        # Create a frame for the text widget with border
        text_frame = tk.Frame(output_frame, bg=self.colors['border'], relief='solid', bd=1)
        text_frame.pack(fill='both', expand=True)
        
        self.encrypt_output = scrolledtext.ScrolledText(text_frame, height=12, width=80, 
                                                       font=('Consolas', 10),
                                                       bg=self.colors['surface'], fg=self.colors['text'],
                                                       relief='flat', bd=0,
                                                       wrap=tk.WORD)
        self.encrypt_output.pack(fill='both', expand=True, padx=2, pady=2)
        
    def create_decrypt_tab(self):
        """Create decryption tab"""
        self.decrypt_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.decrypt_frame, text="🔓 Decrypt")
        
        # Create main content frame
        main_frame = tk.Frame(self.decrypt_frame, bg=self.colors['surface'])
        main_frame.pack(fill='both', expand=True, padx=25, pady=25)
        
        # Instructions section
        instructions_frame = tk.Frame(main_frame, bg=self.colors['surface'])
        instructions_frame.pack(fill='x', pady=(0, 20))
        
        tk.Label(instructions_frame, text="Instructions:", 
                font=('Arial', 13, 'bold'),
                bg=self.colors['surface'], fg=self.colors['text']).pack(anchor='w', pady=(0, 8))
        
        tk.Label(instructions_frame, text="Select at least 2 stego images to decrypt your password.", 
                font=('Arial', 11), fg=self.colors['text_light'],
                bg=self.colors['surface']).pack(anchor='w', pady=(0, 5))
        
        tk.Label(instructions_frame, text="The images must be from the same encryption session.", 
                font=('Arial', 11), fg=self.colors['text_light'],
                bg=self.colors['surface']).pack(anchor='w', pady=(0, 15))
        
        # Image selection section
        selection_frame = tk.Frame(main_frame, bg=self.colors['surface'])
        selection_frame.pack(fill='x', pady=(0, 20))
        
        tk.Label(selection_frame, text="Selected Images:", 
                font=('Arial', 13, 'bold'),
                bg=self.colors['surface'], fg=self.colors['text']).pack(anchor='w', pady=(0, 8))
        
        # Listbox for selected files with better styling
        list_container = tk.Frame(selection_frame, bg=self.colors['border'], relief='solid', bd=1)
        list_container.pack(fill='x', pady=(0, 10))
        
        self.image_listbox = tk.Listbox(list_container, height=5, font=('Arial', 11),
                                      bg=self.colors['surface'], fg=self.colors['text'],
                                      selectbackground=self.colors['accent'],
                                      selectforeground='white',
                                      relief='flat', bd=0)
        scrollbar = tk.Scrollbar(list_container, orient="vertical", command=self.image_listbox.yview,
                               bg=self.colors['surface'])
        self.image_listbox.configure(yscrollcommand=scrollbar.set)
        
        self.image_listbox.pack(side="left", fill="both", expand=True, padx=2, pady=2)
        scrollbar.pack(side="right", fill="y", padx=(0, 2), pady=2)
        
        # Buttons for file selection with better styling
        btn_frame = tk.Frame(selection_frame, bg=self.colors['surface'])
        btn_frame.pack(fill='x', pady=(0, 15))
        
        tk.Button(btn_frame, text="📁 Add Image", command=self.add_image_file,
                 bg=self.colors['success'], fg='white', font=('Arial', 11, 'bold'),
                 padx=20, pady=8, relief='flat',
                 activebackground='#229954', activeforeground='white',
                 cursor='hand2').pack(side='left', padx=(0, 10))
        
        tk.Button(btn_frame, text="🗑️ Remove Selected", command=self.remove_selected_image,
                 bg=self.colors['error'], fg='white', font=('Arial', 11, 'bold'),
                 padx=20, pady=8, relief='flat',
                 activebackground='#c0392b', activeforeground='white',
                 cursor='hand2').pack(side='left')
        
        # Master password section
        password_frame = tk.Frame(main_frame, bg=self.colors['surface'])
        password_frame.pack(fill='x', pady=(0, 20))
        
        tk.Label(password_frame, text="Master Password:", 
                font=('Arial', 13, 'bold'),
                bg=self.colors['surface'], fg=self.colors['text']).pack(anchor='w', pady=(0, 8))
        
        self.decrypt_master_entry = tk.Entry(password_frame, show="*", width=60, font=('Arial', 11),
                                           relief='solid', bd=1, highlightthickness=2,
                                           highlightcolor=self.colors['accent'])
        self.decrypt_master_entry.pack(fill='x', pady=(0, 15))
        
        # Button section
        button_frame = tk.Frame(main_frame, bg=self.colors['surface'])
        button_frame.pack(fill='x', pady=(0, 20))
        
        self.decrypt_btn = tk.Button(button_frame, text="🔓 Start Decryption", 
                                    command=self.start_decryption,
                                    bg=self.colors['success'], fg='white', 
                                    font=('Arial', 13, 'bold'),
                                    padx=30, pady=12, relief='flat',
                                    activebackground='#229954', activeforeground='white',
                                    cursor='hand2')
        self.decrypt_btn.pack(pady=(0, 15))
        
        # Progress bar with custom styling
        self.decrypt_progress = ttk.Progressbar(button_frame, mode='indeterminate',
                                              style='Custom.Horizontal.TProgressbar')
        self.decrypt_progress.pack(fill='x', pady=(0, 15))
        
        # Output area with better styling
        output_frame = tk.Frame(main_frame, bg=self.colors['surface'])
        output_frame.pack(fill='both', expand=True)
        
        tk.Label(output_frame, text="Results:", 
                font=('Arial', 13, 'bold'),
                bg=self.colors['surface'], fg=self.colors['text']).pack(anchor='w', pady=(0, 8))
        
        # Create a frame for the text widget with border
        text_frame = tk.Frame(output_frame, bg=self.colors['border'], relief='solid', bd=1)
        text_frame.pack(fill='both', expand=True)
        
        self.decrypt_output = scrolledtext.ScrolledText(text_frame, height=12, width=80, 
                                                       font=('Consolas', 10),
                                                       bg=self.colors['surface'], fg=self.colors['text'],
                                                       relief='flat', bd=0,
                                                       wrap=tk.WORD)
        self.decrypt_output.pack(fill='both', expand=True, padx=2, pady=2)
        
        # Store selected images
        self.selected_images = []
        
    def create_manual_tab(self):
        """Create manual decryption tab"""
        self.manual_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.manual_frame, text="📁 Manual")
        
        # Create main content frame
        main_frame = tk.Frame(self.manual_frame, bg=self.colors['surface'])
        main_frame.pack(fill='both', expand=True, padx=25, pady=25)
        
        # Instructions section
        instructions_frame = tk.Frame(main_frame, bg=self.colors['surface'])
        instructions_frame.pack(fill='x', pady=(0, 20))
        
        tk.Label(instructions_frame, text="Manual Decryption:", 
                font=('Arial', 13, 'bold'),
                bg=self.colors['surface'], fg=self.colors['text']).pack(anchor='w', pady=(0, 8))
        
        tk.Label(instructions_frame, text="This mode is for decrypting .bin files.", 
                font=('Arial', 11), fg=self.colors['text_light'],
                bg=self.colors['surface']).pack(anchor='w', pady=(0, 5))
        
        tk.Label(instructions_frame, text="Use this if you saved encrypted data without steganography.", 
                font=('Arial', 11), fg=self.colors['text_light'],
                bg=self.colors['surface']).pack(anchor='w', pady=(0, 15))
        
        # File selection section
        file_frame = tk.Frame(main_frame, bg=self.colors['surface'])
        file_frame.pack(fill='x', pady=(0, 20))
        
        tk.Label(file_frame, text="Select .bin file:", 
                font=('Arial', 13, 'bold'),
                bg=self.colors['surface'], fg=self.colors['text']).pack(anchor='w', pady=(0, 8))
        
        file_input_frame = tk.Frame(file_frame, bg=self.colors['surface'])
        file_input_frame.pack(fill='x', pady=(0, 15))
        
        self.manual_file_entry = tk.Entry(file_input_frame, width=50, font=('Arial', 11),
                                        relief='solid', bd=1, highlightthickness=2,
                                        highlightcolor=self.colors['accent'])
        self.manual_file_entry.pack(side='left', fill='x', expand=True, padx=(0, 10))
        
        tk.Button(file_input_frame, text="📁 Browse", command=self.browse_manual_file,
                 bg=self.colors['warning'], fg='white', font=('Arial', 11, 'bold'),
                 padx=20, pady=8, relief='flat',
                 activebackground='#e67e22', activeforeground='white',
                 cursor='hand2').pack(side='right')
        
        # Master password section
        password_frame = tk.Frame(main_frame, bg=self.colors['surface'])
        password_frame.pack(fill='x', pady=(0, 20))
        
        tk.Label(password_frame, text="Master Password:", 
                font=('Arial', 13, 'bold'),
                bg=self.colors['surface'], fg=self.colors['text']).pack(anchor='w', pady=(0, 8))
        
        self.manual_master_entry = tk.Entry(password_frame, show="*", width=60, font=('Arial', 11),
                                          relief='solid', bd=1, highlightthickness=2,
                                          highlightcolor=self.colors['accent'])
        self.manual_master_entry.pack(fill='x', pady=(0, 15))
        
        # Button section
        button_frame = tk.Frame(main_frame, bg=self.colors['surface'])
        button_frame.pack(fill='x', pady=(0, 20))
        
        self.manual_decrypt_btn = tk.Button(button_frame, text="🔓 Decrypt File", 
                                            command=self.start_manual_decryption,
                                            bg=self.colors['success'], fg='white', 
                                            font=('Arial', 13, 'bold'),
                                            padx=30, pady=12, relief='flat',
                                            activebackground='#229954', activeforeground='white',
                                            cursor='hand2')
        self.manual_decrypt_btn.pack(pady=(0, 15))
        
        # Output area with better styling
        output_frame = tk.Frame(main_frame, bg=self.colors['surface'])
        output_frame.pack(fill='both', expand=True)
        
        tk.Label(output_frame, text="Results:", 
                font=('Arial', 13, 'bold'),
                bg=self.colors['surface'], fg=self.colors['text']).pack(anchor='w', pady=(0, 8))
        
        # Create a frame for the text widget with border
        text_frame = tk.Frame(output_frame, bg=self.colors['border'], relief='solid', bd=1)
        text_frame.pack(fill='both', expand=True)
        
        self.manual_output = scrolledtext.ScrolledText(text_frame, height=15, width=80, 
                                                      font=('Consolas', 10),
                                                      bg=self.colors['surface'], fg=self.colors['text'],
                                                      relief='flat', bd=0,
                                                      wrap=tk.WORD)
        self.manual_output.pack(fill='both', expand=True, padx=2, pady=2)
        
    def create_about_tab(self):
        """Create about tab"""
        self.about_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.about_frame, text="ℹ️ About")
        
        # Create main content frame with scrollable content
        main_frame = tk.Frame(self.about_frame, bg=self.colors['surface'])
        main_frame.pack(fill='both', expand=True, padx=25, pady=25)
        
        # Create scrollable frame
        canvas = tk.Canvas(main_frame, bg=self.colors['surface'], highlightthickness=0)
        scrollbar = tk.Scrollbar(main_frame, orient="vertical", command=canvas.yview)
        scrollable_frame = tk.Frame(canvas, bg=self.colors['surface'])
        
        scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )
        
        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        
        # About content with better styling
        about_text = """🔐 Fractured Keys - Offline Password Manager

Fractured Keys is an experimental approach to secure credential storage that avoids traditional single-point vaults. Instead of keeping an encrypted blob in one place, the data is divided, transformed, and distributed across multiple independent carriers.

Key Features:
• Offline security models — no reliance on online services
• Redundancy with thresholds — only partial components are required to recover the whole
• Steganographic concealment — information is embedded where it is least expected
• Layered cryptography — multiple primitives combined to resist straightforward analysis

How it works:
1. Your password is encrypted with AES-GCM using a master password
2. The encrypted data is split into shares using Shamir Secret Sharing
3. Each share is embedded into a different image using steganography
4. You need at least 2 out of 3 images to reconstruct your password

Security:
• Uses Argon2id for key derivation
• AES-GCM for encryption
• Shamir Secret Sharing for redundancy
• LSB steganography for concealment

The result is a system that doesn't resemble a password manager in its raw form — the stored material does not look like secrets at all.

⚠️ This is research-driven software intended for educational and experimental use."""
        
        about_label = tk.Label(scrollable_frame, text=about_text, 
                              font=('Arial', 11), justify='left', 
                              wraplength=750, bg=self.colors['surface'], fg=self.colors['text'])
        about_label.pack(padx=20, pady=20)
        
        # Pack canvas and scrollbar
        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        
    def update_status(self, message):
        """Update status bar"""
        self.status_var.set(message)
        
    def log_output(self, text_widget, message):
        """Add message to output text widget"""
        text_widget.insert(tk.END, message + "\n")
        text_widget.see(tk.END)
        self.root.update_idletasks()
        
    def start_encryption(self):
        """Start encryption process"""
        password = self.password_entry.get().strip()
        master_password = self.master_password_entry.get().strip()
        
        if not password:
            messagebox.showerror("Error", "Please enter a password to encrypt")
            return
            
        if not master_password:
            messagebox.showerror("Error", "Please enter a master password")
            return
            
        # Clear output
        self.encrypt_output.delete(1.0, tk.END)
        
        # Start encryption in thread
        self.encrypt_progress.start()
        self.encrypt_btn.config(state='disabled')
        self.update_status("Encrypting...")
        
        thread = threading.Thread(target=self.encrypt_worker, args=(password, master_password))
        thread.daemon = True
        thread.start()
        
    def encrypt_worker(self, password, master_password):
        """Encryption worker thread"""
        try:
            self.log_output(self.encrypt_output, "🔒 Starting encryption process...")
            
            # Encrypt the password
            self.log_output(self.encrypt_output, "Encrypting password with master password...")
            salt, nonce, ciphertext_with_tag = encrypt_password_aes_gcm(password, master_password)
            
            # Show encryption results
            import base64
            ciphertext = ciphertext_with_tag[:-16]
            auth_tag = ciphertext_with_tag[-16:]
            
            self.log_output(self.encrypt_output, "\n--- ENCRYPTION RESULTS ---")
            self.log_output(self.encrypt_output, f"Salt: {base64.b64encode(salt).decode()}")
            self.log_output(self.encrypt_output, f"Nonce: {base64.b64encode(nonce).decode()}")
            self.log_output(self.encrypt_output, f"Ciphertext: {base64.b64encode(ciphertext).decode()}")
            self.log_output(self.encrypt_output, f"Auth Tag: {base64.b64encode(auth_tag).decode()}")
            
            binary_blob = salt + nonce + ciphertext_with_tag
            
            if self.use_shares_var.get():
                self.log_output(self.encrypt_output, "\n📊 Splitting into SSS shares...")
                self.create_shares_and_embed(binary_blob)
            else:
                # Save as binary file
                filename = "encrypted_output.bin"
                with open(filename, "wb") as f:
                    f.write(binary_blob)
                self.log_output(self.encrypt_output, f"\n✅ Binary file saved: {filename}")
                
        except Exception as e:
            self.log_output(self.encrypt_output, f"❌ Encryption failed: {str(e)}")
        finally:
            self.root.after(0, self.encryption_finished)
            
    def create_shares_and_embed(self, binary_blob):
        """Create shares and embed into images"""
        try:
            import os
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
            
            # Generate ephemeral key and encrypt binary blob
            self.log_output(self.encrypt_output, "Generating ephemeral key and packaging...")
            K2 = os.urandom(16)
            aes = AESGCM(K2)
            nonce2 = os.urandom(12)
            packaged_ct_and_tag = aes.encrypt(nonce2, binary_blob, None)
            packaged_cipher = nonce2 + packaged_ct_and_tag
            
            # Split K2 into shares
            n_shares = 3
            threshold = 2
            self.log_output(self.encrypt_output, f"Splitting ephemeral key into {n_shares} shares (threshold {threshold})...")
            shares = split_bytes_into_shares(K2, n=n_shares, k=threshold)
            
            # For each share, ask user to select carrier image
            for i, share_bytes in enumerate(shares, start=1):
                self.log_output(self.encrypt_output, f"\n📁 Please select carrier image for share {i}/{n_shares}")
                
                # Use file dialog
                file_types = [("Images", ("*.png","*.jpg","*.jpeg","*.bmp","*.tiff")), ("All files", "*.*")]
                carrier_path = filedialog.askopenfilename(
                    title=f"Select carrier image for share {i}",
                    filetypes=file_types
                )
                
                if not carrier_path:
                    self.log_output(self.encrypt_output, f"❌ No carrier selected for share {i}. Skipping.")
                    continue
                    
                # Wrap share with metadata
                payload = self._wrap_share_payload(share_bytes, index=i, total=n_shares, 
                                                 threshold=threshold, packaged_cipher=packaged_cipher)
                
                # Ask for output path
                output_path = filedialog.asksaveasfilename(
                    title=f"Save stego image for share {i}",
                    filetypes=[("PNG image", "*.png"), ("All files", "*.*")],
                    defaultextension=".png"
                )
                
                if not output_path:
                    # Generate default name
                    base = os.path.splitext(carrier_path)[0]
                    output_path = f"{base}_stego_{i}.png"
                
                # Embed data
                saved_path = embed_data_into_image(carrier_path, payload, output_path=output_path)
                self.log_output(self.encrypt_output, f"✅ Share {i} embedded into: {saved_path}")
                
            self.log_output(self.encrypt_output, "\n🎉 All shares processed successfully!")
            self.log_output(self.encrypt_output, "💡 Keep at least 2 of the stego images safe to reconstruct your password.")
            
        except Exception as e:
            self.log_output(self.encrypt_output, f"❌ Share creation failed: {str(e)}")
            
    def _wrap_share_payload(self, share_bytes, index, total, threshold, packaged_cipher):
        """Wrap share payload with metadata"""
        SHARE_MAGIC = b"FKSS01"
        SHARE_VERSION = 1
        
        header = bytearray()
        header += SHARE_MAGIC
        header.append(SHARE_VERSION & 0xFF)
        header.append(index & 0xFF)
        header.append(total & 0xFF)
        header.append(threshold & 0xFF)
        header += len(share_bytes).to_bytes(4, 'big')
        header += len(packaged_cipher).to_bytes(4, 'big')
        return bytes(header) + share_bytes + packaged_cipher
        
    def encryption_finished(self):
        """Called when encryption is finished"""
        self.encrypt_progress.stop()
        self.encrypt_btn.config(state='normal')
        self.update_status("Encryption completed")
        
    def add_image_file(self):
        """Add image file to decryption list"""
        file_types = [("Images", ("*.png","*.jpg","*.jpeg","*.bmp","*.tiff")), ("All files", "*.*")]
        file_path = filedialog.askopenfilename(title="Select stego image", filetypes=file_types)
        
        if file_path and file_path not in self.selected_images:
            self.selected_images.append(file_path)
            self.image_listbox.insert(tk.END, os.path.basename(file_path))
            
    def remove_selected_image(self):
        """Remove selected image from list"""
        selection = self.image_listbox.curselection()
        if selection:
            index = selection[0]
            self.image_listbox.delete(index)
            del self.selected_images[index]
            
    def start_decryption(self):
        """Start decryption process"""
        if len(self.selected_images) < 2:
            messagebox.showerror("Error", "Please select at least 2 stego images")
            return
            
        master_password = self.decrypt_master_entry.get().strip()
        if not master_password:
            messagebox.showerror("Error", "Please enter master password")
            return
            
        # Clear output
        self.decrypt_output.delete(1.0, tk.END)
        
        # Start decryption in thread
        self.decrypt_progress.start()
        self.decrypt_btn.config(state='disabled')
        self.update_status("Decrypting...")
        
        thread = threading.Thread(target=self.decrypt_worker, args=(self.selected_images, master_password))
        thread.daemon = True
        thread.start()
        
    def decrypt_worker(self, image_paths, master_password):
        """Decryption worker thread"""
        try:
            self.log_output(self.decrypt_output, "🔓 Starting decryption process...")
            
            # Extract share payloads
            parsed_shares = []
            for path in image_paths:
                self.log_output(self.decrypt_output, f"Extracting data from: {os.path.basename(path)}")
                payload = extract_data_from_image(path)
                meta = self._parse_share_payload(payload)
                parsed_shares.append(meta)
                self.log_output(self.decrypt_output, f"Found share {meta['index']}/{meta['total']} (threshold={meta['threshold']})")
                
            # Validate shares
            if len(parsed_shares) < 2:
                self.log_output(self.decrypt_output, "❌ Not enough valid shares found")
                return
                
            # Check compatibility
            vs = {s['version'] for s in parsed_shares}
            totals = {s['total'] for s in parsed_shares}
            thresholds = {s['threshold'] for s in parsed_shares}
            pkg_hashes = {s['packaged_cipher'] for s in parsed_shares}
            
            if len(vs) != 1 or len(totals) != 1 or len(thresholds) != 1 or len(pkg_hashes) != 1:
                self.log_output(self.decrypt_output, "❌ Selected shares do not match")
                return
                
            threshold = parsed_shares[0]['threshold']
            if len(parsed_shares) < threshold:
                self.log_output(self.decrypt_output, f"❌ Need at least {threshold} shares")
                return
                
            # Recover ephemeral key
            self.log_output(self.decrypt_output, "🔑 Recovering ephemeral key from shares...")
            share_bytes_list = [s['share_bytes'] for s in parsed_shares[:threshold]]
            packaged_cipher = parsed_shares[0]['packaged_cipher']
            
            recovered_k2 = recover_bytes_from_shares(share_bytes_list)
            if len(recovered_k2) < 16:
                recovered_k2 = (b'\x00' * (16 - len(recovered_k2))) + recovered_k2
            elif len(recovered_k2) > 16:
                recovered_k2 = recovered_k2[-16:]
                
            # Decrypt packaged cipher
            self.log_output(self.decrypt_output, "📦 Decrypting packaged data...")
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
            aes = AESGCM(recovered_k2)
            nonce2 = packaged_cipher[:12]
            ct_and_tag = packaged_cipher[12:]
            binary_blob = aes.decrypt(nonce2, ct_and_tag, None)
            
            # Parse binary blob
            salt = binary_blob[:16]
            nonce = binary_blob[16:28]
            ciphertext_with_tag = binary_blob[28:]
            
            # Decrypt with master password
            self.log_output(self.decrypt_output, "🔐 Decrypting with master password...")
            plaintext = decrypt_password_aes_gcm(salt, nonce, ciphertext_with_tag, master_password)
            
            self.log_output(self.decrypt_output, "\n🎉 DECRYPTION SUCCESSFUL!")
            self.log_output(self.decrypt_output, f"🔑 Decrypted password: {plaintext}")
            self.log_output(self.decrypt_output, f"📏 Password length: {len(plaintext)} characters")
            
        except Exception as e:
            self.log_output(self.decrypt_output, f"❌ Decryption failed: {str(e)}")
        finally:
            self.root.after(0, self.decryption_finished)
            
    def _parse_share_payload(self, payload):
        """Parse wrapped share payload"""
        SHARE_MAGIC = b"FKSS01"
        SHARE_MAGIC_LEN = len(SHARE_MAGIC)
        
        min_header = SHARE_MAGIC_LEN + 1 + 1 + 1 + 1 + 4 + 4
        if len(payload) < min_header:
            raise ValueError("Share payload too short")
        if payload[:SHARE_MAGIC_LEN] != SHARE_MAGIC:
            raise ValueError("Share magic mismatch")
            
        pos = SHARE_MAGIC_LEN
        version = payload[pos]; pos += 1
        index = payload[pos]; pos += 1
        total = payload[pos]; pos += 1
        threshold = payload[pos]; pos += 1
        share_len = int.from_bytes(payload[pos:pos+4], 'big'); pos += 4
        packaged_cipher_len = int.from_bytes(payload[pos:pos+4], 'big'); pos += 4
        
        if pos + share_len + packaged_cipher_len > len(payload):
            raise ValueError("Declared sizes exceed payload size")
            
        share_bytes = payload[pos:pos+share_len]; pos += share_len
        packaged_cipher = payload[pos:pos+packaged_cipher_len]
        
        return {
            "version": version,
            "index": index,
            "total": total,
            "threshold": threshold,
            "share_len": share_len,
            "packaged_cipher_len": packaged_cipher_len,
            "share_bytes": share_bytes,
            "packaged_cipher": packaged_cipher
        }
        
    def decryption_finished(self):
        """Called when decryption is finished"""
        self.decrypt_progress.stop()
        self.decrypt_btn.config(state='normal')
        self.update_status("Decryption completed")
        
    def browse_manual_file(self):
        """Browse for manual decryption file"""
        file_path = filedialog.askopenfilename(
            title="Select .bin file for decryption",
            filetypes=[("Binary files", "*.bin"), ("All files", "*.*")]
        )
        if file_path:
            self.manual_file_entry.delete(0, tk.END)
            self.manual_file_entry.insert(0, file_path)
            
    def start_manual_decryption(self):
        """Start manual decryption"""
        file_path = self.manual_file_entry.get().strip()
        master_password = self.manual_master_entry.get().strip()
        
        if not file_path:
            messagebox.showerror("Error", "Please select a .bin file")
            return
            
        if not master_password:
            messagebox.showerror("Error", "Please enter master password")
            return
            
        # Clear output
        self.manual_output.delete(1.0, tk.END)
        
        try:
            self.log_output(self.manual_output, "🔓 Starting manual decryption...")
            
            # Read binary file
            with open(file_path, "rb") as f:
                binary_blob = f.read()
                
            if len(binary_blob) < 28:
                self.log_output(self.manual_output, "❌ File too small to be valid")
                return
                
            # Parse binary blob
            salt = binary_blob[:16]
            nonce = binary_blob[16:28]
            ciphertext_with_tag = binary_blob[28:]
            
            # Decrypt
            self.log_output(self.manual_output, "🔐 Decrypting with master password...")
            plaintext = decrypt_password_aes_gcm(salt, nonce, ciphertext_with_tag, master_password)
            
            self.log_output(self.manual_output, "\n🎉 DECRYPTION SUCCESSFUL!")
            self.log_output(self.manual_output, f"🔑 Decrypted password: {plaintext}")
            self.log_output(self.manual_output, f"📏 Password length: {len(plaintext)} characters")
            
        except Exception as e:
            self.log_output(self.manual_output, f"❌ Manual decryption failed: {str(e)}")

def main():
    """Main function to run the GUI"""
    root = tk.Tk()
    app = SimpleFracturedKeysGUI(root)
    
    # Handle window closing
    def on_closing():
        try:
            if messagebox.askokcancel("Quit", "Do you want to quit Fractured Keys?"):
                root.destroy()
        except:
            # If there's an error with the messagebox, just destroy the window
            root.destroy()
    
    root.protocol("WM_DELETE_WINDOW", on_closing)
    root.mainloop()

if __name__ == "__main__":
    main()
