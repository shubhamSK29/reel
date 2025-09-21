#!/usr/bin/env python3
"""
Fractured Keys - Modern Attractive GUI
A reliable, modern-looking GUI for the password manager
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

class ModernFracturedKeysGUI:
    def __init__(self, root):
        self.root = root
        self.setup_window()
        self.create_widgets()
        
    def setup_window(self):
        """Configure the main window"""
        self.root.title("🔐 Fractured Keys - Secure Password Manager")
        self.root.geometry("1000x750")
        self.root.configure(bg='#f8fafc')
        
        # Center the window
        self.root.update_idletasks()
        x = (self.root.winfo_screenwidth() // 2) - (1000 // 2)
        y = (self.root.winfo_screenheight() // 2) - (750 // 2)
        self.root.geometry(f"1000x750+{x}+{y}")
        
        # Add window icon and styling
        self.root.resizable(True, True)
        self.root.minsize(900, 650)
        
    def create_widgets(self):
        """Create all GUI widgets"""
        # Beautiful gradient-like header with shadow effect
        header_frame = tk.Frame(self.root, bg='#1a252f', height=120)
        header_frame.pack(fill='x', pady=(0, 25))
        header_frame.pack_propagate(False)
        
        # Add shadow effect frame
        shadow_frame = tk.Frame(self.root, bg='#34495e', height=2)
        shadow_frame.pack(fill='x', pady=(0, 23))
        
        # Main header content
        header_content = tk.Frame(header_frame, bg='#1a252f')
        header_content.pack(expand=True, fill='both')
        
        # Beautiful title with gradient effect simulation
        title_label = tk.Label(header_content, text="🔐 Fractured Keys", 
                              font=('Arial', 28, 'bold'), 
                              bg='#1a252f', fg='#ecf0f1')
        title_label.pack(pady=(25, 8))
        
        # Subtitle with better styling
        subtitle_label = tk.Label(header_content, text="✨ Modern Password Manager with Steganography ✨", 
                                 font=('Arial', 13), 
                                 bg='#1a252f', fg='#95a5a6')
        subtitle_label.pack(pady=(0, 25))
        
        # Create beautiful notebook for tabs with custom styling
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill='both', expand=True, padx=35, pady=(0, 25))
        
        # Create tabs
        self.create_encrypt_tab()
        self.create_decrypt_tab()
        self.create_manual_tab()
        self.create_about_tab()
        
        # Beautiful status bar with gradient effect
        status_frame = tk.Frame(self.root, bg='#2c3e50', height=40)
        status_frame.pack(side=tk.BOTTOM, fill=tk.X)
        status_frame.pack_propagate(False)
        
        # Status bar content
        status_content = tk.Frame(status_frame, bg='#2c3e50')
        status_content.pack(expand=True, fill='both', padx=20, pady=8)
        
        self.status_var = tk.StringVar()
        self.status_var.set("✨ Ready - Fractured Keys is running smoothly")
        status_bar = tk.Label(status_content, textvariable=self.status_var, 
                             anchor=tk.W, 
                             bg='#2c3e50', fg='#ecf0f1',
                             font=('Arial', 11))
        status_bar.pack(side=tk.LEFT)
        
        # Add a small indicator
        indicator = tk.Label(status_content, text="●", 
                           bg='#2c3e50', fg='#27ae60',
                           font=('Arial', 12))
        indicator.pack(side=tk.RIGHT, padx=(10, 0))
        
    def create_encrypt_tab(self):
        """Create encryption tab"""
        self.encrypt_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.encrypt_frame, text="🔒 Encrypt")
        
        # Beautiful main content frame with subtle border
        main_frame = tk.Frame(self.encrypt_frame, bg='#ffffff', relief='flat', bd=0)
        main_frame.pack(fill='both', expand=True, padx=30, pady=30)
        
        # Add subtle shadow effect
        shadow_frame = tk.Frame(self.encrypt_frame, bg='#e8f4f8', height=2)
        shadow_frame.pack(fill='x', padx=30, pady=(0, 28))
        
        # Beautiful password input section with cards
        input_frame = tk.Frame(main_frame, bg='#f8fafc')
        input_frame.pack(fill='x', pady=(0, 25))
        
        # Password card
        password_card = tk.Frame(input_frame, bg='#ffffff', relief='flat', bd=1)
        password_card.pack(fill='x', pady=(0, 15))
        
        tk.Label(password_card, text="🔑 Password to Encrypt:", 
                font=('Arial', 14, 'bold'), 
                bg='#ffffff', fg='#2c3e50').pack(anchor='w', padx=20, pady=(15, 10))
        
        self.password_entry = tk.Entry(password_card, show="*", width=60, font=('Arial', 12),
                                     relief='flat', bd=2, highlightthickness=3,
                                     highlightcolor='#3498db', highlightbackground='#e3f2fd',
                                     bg='#f8fafc', fg='#2c3e50')
        self.password_entry.pack(fill='x', padx=20, pady=(0, 15))
        
        # Master password card
        master_card = tk.Frame(input_frame, bg='#ffffff', relief='flat', bd=1)
        master_card.pack(fill='x', pady=(0, 15))
        
        tk.Label(master_card, text="🔐 Master Password:", 
                font=('Arial', 14, 'bold'),
                bg='#ffffff', fg='#2c3e50').pack(anchor='w', padx=20, pady=(15, 10))
        
        self.master_password_entry = tk.Entry(master_card, show="*", width=60, font=('Arial', 12),
                                            relief='flat', bd=2, highlightthickness=3,
                                            highlightcolor='#3498db', highlightbackground='#e3f2fd',
                                            bg='#f8fafc', fg='#2c3e50')
        self.master_password_entry.pack(fill='x', padx=20, pady=(0, 15))
        
        # Beautiful options section with card design
        options_card = tk.Frame(main_frame, bg='#ffffff', relief='flat', bd=1)
        options_card.pack(fill='x', pady=(0, 25))
        
        tk.Label(options_card, text="⚙️ Encryption Options:", 
                font=('Arial', 14, 'bold'),
                bg='#ffffff', fg='#2c3e50').pack(anchor='w', padx=20, pady=(15, 10))
        
        self.use_shares_var = tk.BooleanVar(value=True)
        shares_check = tk.Checkbutton(options_card, 
                                     text="📊 Split into 3 shares and embed into images", 
                                     variable=self.use_shares_var,
                                     font=('Arial', 12),
                                     bg='#ffffff', fg='#2c3e50',
                                     selectcolor='#3498db',
                                     activebackground='#ffffff')
        shares_check.pack(anchor='w', padx=20, pady=(0, 8))
        
        tk.Label(options_card, text="💡 This will create 3 stego images. You need at least 2 to decrypt.", 
                font=('Arial', 11), fg='#7f8c8d',
                bg='#ffffff').pack(anchor='w', padx=40, pady=(0, 15))
        
        # Beautiful button section with gradient effect
        button_card = tk.Frame(main_frame, bg='#ffffff', relief='flat', bd=1)
        button_card.pack(fill='x', pady=(0, 25))
        
        tk.Label(button_card, text="🚀 Actions:", 
                font=('Arial', 14, 'bold'),
                bg='#ffffff', fg='#2c3e50').pack(anchor='w', padx=20, pady=(15, 10))
        
        # Beautiful encrypt button with modern styling
        self.encrypt_btn = tk.Button(button_card, text="🔒 Start Encryption", 
                                    command=self.start_encryption,
                                    bg='#3498db', fg='white', 
                                    font=('Arial', 14, 'bold'),
                                    padx=40, pady=15, relief='flat',
                                    activebackground='#2980b9', activeforeground='white',
                                    cursor='hand2', bd=0)
        self.encrypt_btn.pack(pady=(0, 15))
        
        # Beautiful progress bar with custom styling
        progress_frame = tk.Frame(button_card, bg='#ffffff')
        progress_frame.pack(fill='x', padx=20, pady=(0, 15))
        
        self.encrypt_progress = ttk.Progressbar(progress_frame, mode='indeterminate',
                                              style='Custom.Horizontal.TProgressbar')
        self.encrypt_progress.pack(fill='x')
        
        # Beautiful output area with card design - MORE PROMINENT
        output_card = tk.Frame(main_frame, bg='#ffffff', relief='solid', bd=2)
        output_card.pack(fill='both', expand=True)
        
        # Make output header more prominent
        output_header = tk.Frame(output_card, bg='#3498db', height=50)
        output_header.pack(fill='x')
        output_header.pack_propagate(False)
        
        tk.Label(output_header, text="📋 ENCRYPTION OUTPUT", 
                font=('Arial', 16, 'bold'),
                bg='#3498db', fg='white').pack(expand=True)
        
        # Beautiful text widget with enhanced visibility
        text_container = tk.Frame(output_card, bg='#2c3e50', relief='flat', bd=1)
        text_container.pack(fill='both', expand=True, padx=5, pady=5)
        
        self.encrypt_output = scrolledtext.ScrolledText(text_container, height=15, width=80, 
                                                       font=('Consolas', 12, 'bold'),
                                                       bg='#1a252f', fg='#00ff00',
                                                       relief='flat', bd=0,
                                                       wrap=tk.WORD,
                                                       selectbackground='#3498db',
                                                       selectforeground='white',
                                                       insertbackground='white')
        self.encrypt_output.pack(fill='both', expand=True, padx=3, pady=3)
        
        # Add initial message to make it clear the output is working
        self.encrypt_output.insert(tk.END, "🔒 Encryption output will appear here...\n")
        self.encrypt_output.insert(tk.END, "📝 Ready to encrypt your password!\n\n")
        
    def create_decrypt_tab(self):
        """Create decryption tab"""
        self.decrypt_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.decrypt_frame, text="🔓 Decrypt")
        
        # Beautiful main content frame
        main_frame = tk.Frame(self.decrypt_frame, bg='#ffffff', relief='flat', bd=0)
        main_frame.pack(fill='both', expand=True, padx=30, pady=30)
        
        # Add subtle shadow effect
        shadow_frame = tk.Frame(self.decrypt_frame, bg='#e8f4f8', height=2)
        shadow_frame.pack(fill='x', padx=30, pady=(0, 28))
        
        # Beautiful instructions section with card design
        instructions_card = tk.Frame(main_frame, bg='#ffffff', relief='flat', bd=1)
        instructions_card.pack(fill='x', pady=(0, 25))
        
        tk.Label(instructions_card, text="📖 Instructions:", 
                font=('Arial', 14, 'bold'),
                bg='#ffffff', fg='#2c3e50').pack(anchor='w', padx=20, pady=(15, 10))
        
        tk.Label(instructions_card, text="🖼️ Select at least 2 stego images to decrypt your password.", 
                font=('Arial', 12), fg='#7f8c8d',
                bg='#ffffff').pack(anchor='w', padx=20, pady=(0, 5))
        
        tk.Label(instructions_card, text="⚠️ The images must be from the same encryption session.", 
                font=('Arial', 12), fg='#7f8c8d',
                bg='#ffffff').pack(anchor='w', padx=20, pady=(0, 15))
        
        # Beautiful image selection section with card design
        selection_card = tk.Frame(main_frame, bg='#ffffff', relief='flat', bd=1)
        selection_card.pack(fill='x', pady=(0, 25))
        
        tk.Label(selection_card, text="🖼️ Selected Images:", 
                font=('Arial', 14, 'bold'),
                bg='#ffffff', fg='#2c3e50').pack(anchor='w', padx=20, pady=(15, 10))
        
        # Beautiful listbox for selected files
        list_container = tk.Frame(selection_card, bg='#f8fafc', relief='flat', bd=1)
        list_container.pack(fill='x', padx=20, pady=(0, 15))
        
        self.image_listbox = tk.Listbox(list_container, height=5, font=('Arial', 12),
                                      bg='#ffffff', fg='#2c3e50',
                                      selectbackground='#3498db',
                                      selectforeground='white',
                                      relief='flat', bd=0)
        scrollbar = tk.Scrollbar(list_container, orient="vertical", command=self.image_listbox.yview,
                               bg='#f8fafc')
        self.image_listbox.configure(yscrollcommand=scrollbar.set)
        
        self.image_listbox.pack(side="left", fill="both", expand=True, padx=2, pady=2)
        scrollbar.pack(side="right", fill="y", padx=(0, 2), pady=2)
        
        # Beautiful buttons for file selection
        btn_frame = tk.Frame(selection_card, bg='#ffffff')
        btn_frame.pack(fill='x', padx=20, pady=(0, 15))
        
        tk.Button(btn_frame, text="📁 Add Image", command=self.add_image_file,
                 bg='#27ae60', fg='white', font=('Arial', 12, 'bold'),
                 padx=25, pady=10, relief='flat',
                 activebackground='#229954', activeforeground='white',
                 cursor='hand2', bd=0).pack(side='left', padx=(0, 15))
        
        tk.Button(btn_frame, text="🗑️ Remove Selected", command=self.remove_selected_image,
                 bg='#e74c3c', fg='white', font=('Arial', 12, 'bold'),
                 padx=25, pady=10, relief='flat',
                 activebackground='#c0392b', activeforeground='white',
                 cursor='hand2', bd=0).pack(side='left')
        
        # Beautiful master password section with card design
        password_card = tk.Frame(main_frame, bg='#ffffff', relief='flat', bd=1)
        password_card.pack(fill='x', pady=(0, 25))
        
        tk.Label(password_card, text="🔐 Master Password:", 
                font=('Arial', 14, 'bold'),
                bg='#ffffff', fg='#2c3e50').pack(anchor='w', padx=20, pady=(15, 10))
        
        self.decrypt_master_entry = tk.Entry(password_card, show="*", width=60, font=('Arial', 12),
                                           relief='flat', bd=2, highlightthickness=3,
                                           highlightcolor='#3498db', highlightbackground='#e3f2fd',
                                           bg='#f8fafc', fg='#2c3e50')
        self.decrypt_master_entry.pack(fill='x', padx=20, pady=(0, 15))
        
        # Beautiful button section with card design
        button_card = tk.Frame(main_frame, bg='#ffffff', relief='flat', bd=1)
        button_card.pack(fill='x', pady=(0, 25))
        
        tk.Label(button_card, text="🚀 Actions:", 
                font=('Arial', 14, 'bold'),
                bg='#ffffff', fg='#2c3e50').pack(anchor='w', padx=20, pady=(15, 10))
        
        # Beautiful decrypt button with modern styling
        self.decrypt_btn = tk.Button(button_card, text="🔓 Start Decryption", 
                                    command=self.start_decryption,
                                    bg='#27ae60', fg='white', 
                                    font=('Arial', 14, 'bold'),
                                    padx=40, pady=15, relief='flat',
                                    activebackground='#229954', activeforeground='white',
                                    cursor='hand2', bd=0)
        self.decrypt_btn.pack(pady=(0, 15))
        
        # Beautiful progress bar with custom styling
        progress_frame = tk.Frame(button_card, bg='#ffffff')
        progress_frame.pack(fill='x', padx=20, pady=(0, 15))
        
        self.decrypt_progress = ttk.Progressbar(progress_frame, mode='indeterminate',
                                              style='Custom.Horizontal.TProgressbar')
        self.decrypt_progress.pack(fill='x')
        
        # ULTRA PROMINENT DECRYPTION OUTPUT AREA
        output_card = tk.Frame(main_frame, bg='#ffffff', relief='raised', bd=3)
        output_card.pack(fill='both', expand=True, pady=(10, 0))
        
        # Make output header EXTREMELY prominent
        output_header = tk.Frame(output_card, bg='#e74c3c', height=60)
        output_header.pack(fill='x')
        output_header.pack_propagate(False)
        
        # Add blinking effect simulation with bold text
        header_label = tk.Label(output_header, text="🔓 DECRYPTION RESULTS - OUTPUT HERE", 
                               font=('Arial', 18, 'bold'),
                               bg='#e74c3c', fg='white')
        header_label.pack(expand=True)
        
        # Add a subtitle for extra visibility
        subtitle_label = tk.Label(output_header, text="↓ Scroll down to see decrypted password ↓", 
                                 font=('Arial', 12),
                                 bg='#e74c3c', fg='#f39c12')
        subtitle_label.pack()
        
        # ULTRA VISIBLE text widget with maximum contrast
        text_container = tk.Frame(output_card, bg='#000000', relief='sunken', bd=2)
        text_container.pack(fill='both', expand=True, padx=8, pady=8)
        
        self.decrypt_output = scrolledtext.ScrolledText(text_container, height=20, width=90, 
                                                       font=('Consolas', 14, 'bold'),
                                                       bg='#000000', fg='#00ff00',
                                                       relief='flat', bd=0,
                                                       wrap=tk.WORD,
                                                       selectbackground='#ff0000',
                                                       selectforeground='#ffffff',
                                                       insertbackground='#ffffff',
                                                       cursor='xterm')
        self.decrypt_output.pack(fill='both', expand=True, padx=5, pady=5)
        
        # Add VERY CLEAR initial message
        self.decrypt_output.insert(tk.END, "🔓 DECRYPTION OUTPUT AREA - READY!\n")
        self.decrypt_output.insert(tk.END, "=" * 60 + "\n")
        self.decrypt_output.insert(tk.END, "📝 INSTRUCTIONS:\n")
        self.decrypt_output.insert(tk.END, "1. Select at least 2 stego images above\n")
        self.decrypt_output.insert(tk.END, "2. Enter your master password\n")
        self.decrypt_output.insert(tk.END, "3. Click 'Start Decryption'\n")
        self.decrypt_output.insert(tk.END, "4. Watch this area for results!\n")
        self.decrypt_output.insert(tk.END, "=" * 60 + "\n")
        self.decrypt_output.insert(tk.END, "🎯 YOUR DECRYPTED PASSWORD WILL APPEAR BELOW:\n")
        self.decrypt_output.insert(tk.END, "=" * 60 + "\n\n")
        
        # Store selected images
        self.selected_images = []
        
    def create_manual_tab(self):
        """Create manual decryption tab"""
        self.manual_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.manual_frame, text="📁 Manual")
        
        # Main content frame
        main_frame = tk.Frame(self.manual_frame, bg='white')
        main_frame.pack(fill='both', expand=True, padx=25, pady=25)
        
        # Instructions section
        instructions_frame = tk.Frame(main_frame, bg='white')
        instructions_frame.pack(fill='x', pady=(0, 20))
        
        tk.Label(instructions_frame, text="Manual Decryption:", 
                font=('Arial', 13, 'bold'),
                bg='white', fg='#2c3e50').pack(anchor='w', pady=(0, 8))
        
        tk.Label(instructions_frame, text="This mode is for decrypting .bin files.", 
                font=('Arial', 11), fg='#7f8c8d',
                bg='white').pack(anchor='w', pady=(0, 5))
        
        tk.Label(instructions_frame, text="Use this if you saved encrypted data without steganography.", 
                font=('Arial', 11), fg='#7f8c8d',
                bg='white').pack(anchor='w', pady=(0, 15))
        
        # File selection section
        file_frame = tk.Frame(main_frame, bg='white')
        file_frame.pack(fill='x', pady=(0, 20))
        
        tk.Label(file_frame, text="Select .bin file:", 
                font=('Arial', 13, 'bold'),
                bg='white', fg='#2c3e50').pack(anchor='w', pady=(0, 8))
        
        file_input_frame = tk.Frame(file_frame, bg='white')
        file_input_frame.pack(fill='x', pady=(0, 15))
        
        self.manual_file_entry = tk.Entry(file_input_frame, width=50, font=('Arial', 11),
                                        relief='solid', bd=2, highlightthickness=2,
                                        highlightcolor='#3498db')
        self.manual_file_entry.pack(side='left', fill='x', expand=True, padx=(0, 10))
        
        tk.Button(file_input_frame, text="📁 Browse", command=self.browse_manual_file,
                 bg='#f39c12', fg='white', font=('Arial', 11, 'bold'),
                 padx=20, pady=8, relief='flat',
                 activebackground='#e67e22', activeforeground='white',
                 cursor='hand2').pack(side='right')
        
        # Master password section
        password_frame = tk.Frame(main_frame, bg='white')
        password_frame.pack(fill='x', pady=(0, 20))
        
        tk.Label(password_frame, text="Master Password:", 
                font=('Arial', 13, 'bold'),
                bg='white', fg='#2c3e50').pack(anchor='w', pady=(0, 8))
        
        self.manual_master_entry = tk.Entry(password_frame, show="*", width=60, font=('Arial', 11),
                                          relief='solid', bd=2, highlightthickness=2,
                                          highlightcolor='#3498db')
        self.manual_master_entry.pack(fill='x', pady=(0, 15))
        
        # Button section
        button_frame = tk.Frame(main_frame, bg='white')
        button_frame.pack(fill='x', pady=(0, 20))
        
        self.manual_decrypt_btn = tk.Button(button_frame, text="🔓 Decrypt File", 
                                            command=self.start_manual_decryption,
                                            bg='#27ae60', fg='white', 
                                            font=('Arial', 13, 'bold'),
                                            padx=30, pady=12, relief='flat',
                                            activebackground='#229954', activeforeground='white',
                                            cursor='hand2')
        self.manual_decrypt_btn.pack(pady=(0, 15))
        
        # Beautiful output area with card design - MORE PROMINENT
        output_card = tk.Frame(main_frame, bg='#ffffff', relief='solid', bd=2)
        output_card.pack(fill='both', expand=True)
        
        # Make output header more prominent
        output_header = tk.Frame(output_card, bg='#f39c12', height=50)
        output_header.pack(fill='x')
        output_header.pack_propagate(False)
        
        tk.Label(output_header, text="📋 MANUAL DECRYPTION RESULTS", 
                font=('Arial', 16, 'bold'),
                bg='#f39c12', fg='white').pack(expand=True)
        
        # Beautiful text widget with enhanced visibility
        text_container = tk.Frame(output_card, bg='#2c3e50', relief='flat', bd=1)
        text_container.pack(fill='both', expand=True, padx=5, pady=5)
        
        self.manual_output = scrolledtext.ScrolledText(text_container, height=15, width=80, 
                                                      font=('Consolas', 12, 'bold'),
                                                      bg='#1a252f', fg='#00ff00',
                                                      relief='flat', bd=0,
                                                      wrap=tk.WORD,
                                                      selectbackground='#3498db',
                                                      selectforeground='white',
                                                      insertbackground='white')
        self.manual_output.pack(fill='both', expand=True, padx=3, pady=3)
        
        # Add initial message to make it clear the output is working
        self.manual_output.insert(tk.END, "🔓 Manual decryption results will appear here...\n")
        self.manual_output.insert(tk.END, "📝 Select a .bin file and enter master password to decrypt!\n\n")
        
    def create_about_tab(self):
        """Create about tab"""
        self.about_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.about_frame, text="ℹ️ About")
        
        # Main content frame
        main_frame = tk.Frame(self.about_frame, bg='white')
        main_frame.pack(fill='both', expand=True, padx=25, pady=25)
        
        # About content
        about_text = """🔐 Fractured Keys - Modern Password Manager

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
        
        about_label = tk.Label(main_frame, text=about_text, 
                              font=('Arial', 11), justify='left', 
                              wraplength=750, bg='white', fg='#2c3e50')
        about_label.pack(padx=20, pady=20)
        
    def update_status(self, message):
        """Update status bar"""
        self.status_var.set(message)
        
    def log_output(self, text_widget, message):
        """Add message to output text widget with enhanced visibility"""
        # Add timestamp for better tracking
        import datetime
        timestamp = datetime.datetime.now().strftime("%H:%M:%S")
        
        # Format the message with timestamp
        formatted_message = f"[{timestamp}] {message}\n"
        
        # Insert the message
        text_widget.insert(tk.END, formatted_message)
        
        # Auto-scroll to bottom
        text_widget.see(tk.END)
        
        # Force update to make sure it's visible
        self.root.update_idletasks()
        
        # Add a small delay to make the output more visible
        self.root.after(10, lambda: None)
        
        # Special handling for decryption output to make it EXTRA visible
        if text_widget == self.decrypt_output:
            # Force focus on the decryption output
            text_widget.focus_set()
            # Ensure the widget is visible
            text_widget.see(tk.END)
            # Force a more aggressive update
            self.root.update()
        
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
            self.log_output(self.encrypt_output, "🔒 STARTING ENCRYPTION PROCESS...")
            self.log_output(self.encrypt_output, "=" * 50)
            
            # Encrypt the password
            self.log_output(self.encrypt_output, "🔐 Encrypting password with master password...")
            self.log_output(self.encrypt_output, f"📏 Password length: {len(password)} characters")
            self.log_output(self.encrypt_output, f"🔑 Master password length: {len(master_password)} characters")
            
            salt, nonce, ciphertext_with_tag = encrypt_password_aes_gcm(password, master_password)
            
            # Show encryption results
            import base64
            ciphertext = ciphertext_with_tag[:-16]
            auth_tag = ciphertext_with_tag[-16:]
            
            self.log_output(self.encrypt_output, "\n🎉 ENCRYPTION SUCCESSFUL!")
            self.log_output(self.encrypt_output, "=" * 50)
            self.log_output(self.encrypt_output, "📊 ENCRYPTION DETAILS:")
            self.log_output(self.encrypt_output, f"🔸 Salt: {base64.b64encode(salt).decode()}")
            self.log_output(self.encrypt_output, f"🔸 Nonce: {base64.b64encode(nonce).decode()}")
            self.log_output(self.encrypt_output, f"🔸 Ciphertext: {base64.b64encode(ciphertext).decode()}")
            self.log_output(self.encrypt_output, f"🔸 Auth Tag: {base64.b64encode(auth_tag).decode()}")
            self.log_output(self.encrypt_output, f"🔸 Total size: {len(salt + nonce + ciphertext_with_tag)} bytes")
            
            binary_blob = salt + nonce + ciphertext_with_tag
            
            if self.use_shares_var.get():
                self.log_output(self.encrypt_output, "\n📊 SPLITTING INTO SSS SHARES...")
                self.log_output(self.encrypt_output, "=" * 50)
                self.create_shares_and_embed(binary_blob)
            else:
                # Save as binary file
                filename = "encrypted_output.bin"
                with open(filename, "wb") as f:
                    f.write(binary_blob)
                self.log_output(self.encrypt_output, f"\n✅ BINARY FILE SAVED: {filename}")
                self.log_output(self.encrypt_output, f"📁 File size: {len(binary_blob)} bytes")
                
        except Exception as e:
            self.log_output(self.encrypt_output, f"\n❌ ENCRYPTION FAILED: {str(e)}")
            self.log_output(self.encrypt_output, "=" * 50)
        finally:
            self.root.after(0, self.encryption_finished)
            
    def create_shares_and_embed(self, binary_blob):
        """Create shares and embed into images"""
        try:
            import os
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
            
            # Generate ephemeral key and encrypt binary blob
            self.log_output(self.encrypt_output, "🔑 Generating ephemeral key and packaging...")
            K2 = os.urandom(16)
            aes = AESGCM(K2)
            nonce2 = os.urandom(12)
            packaged_ct_and_tag = aes.encrypt(nonce2, binary_blob, None)
            packaged_cipher = nonce2 + packaged_ct_and_tag
            
            self.log_output(self.encrypt_output, f"📦 Packaged data size: {len(packaged_cipher)} bytes")
            
            # Split K2 into shares
            n_shares = 3
            threshold = 2
            self.log_output(self.encrypt_output, f"📊 Splitting ephemeral key into {n_shares} shares (threshold {threshold})...")
            shares = split_bytes_into_shares(K2, n=n_shares, k=threshold)
            
            self.log_output(self.encrypt_output, f"✅ Generated {len(shares)} shares successfully!")
            
            # For each share, ask user to select carrier image
            for i, share_bytes in enumerate(shares, start=1):
                self.log_output(self.encrypt_output, f"\n📁 SHARE {i}/{n_shares} - Please select carrier image...")
                self.log_output(self.encrypt_output, f"🔸 Share size: {len(share_bytes)} bytes")
                
                # Use file dialog
                file_types = [("Images", ("*.png","*.jpg","*.jpeg","*.bmp","*.tiff")), ("All files", "*.*")]
                carrier_path = filedialog.askopenfilename(
                    title=f"Select carrier image for share {i}",
                    filetypes=file_types
                )
                
                if not carrier_path:
                    self.log_output(self.encrypt_output, f"❌ No carrier selected for share {i}. Skipping.")
                    continue
                    
                self.log_output(self.encrypt_output, f"🖼️ Selected carrier: {os.path.basename(carrier_path)}")
                
                # Wrap share with metadata
                payload = self._wrap_share_payload(share_bytes, index=i, total=n_shares, 
                                                 threshold=threshold, packaged_cipher=packaged_cipher)
                
                self.log_output(self.encrypt_output, f"📦 Total payload size: {len(payload)} bytes")
                
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
                
                self.log_output(self.encrypt_output, f"💾 Saving to: {os.path.basename(output_path)}")
                
                # Embed data
                saved_path = embed_data_into_image(carrier_path, payload, output_path=output_path)
                self.log_output(self.encrypt_output, f"✅ Share {i} embedded successfully!")
                self.log_output(self.encrypt_output, f"📁 Saved as: {saved_path}")
                
            self.log_output(self.encrypt_output, "\n🎉 ALL SHARES PROCESSED SUCCESSFULLY!")
            self.log_output(self.encrypt_output, "=" * 50)
            self.log_output(self.encrypt_output, "💡 IMPORTANT: Keep at least 2 of the stego images safe!")
            self.log_output(self.encrypt_output, "🔐 You need at least 2 images to reconstruct your password.")
            self.log_output(self.encrypt_output, "=" * 50)
            
        except Exception as e:
            self.log_output(self.encrypt_output, f"\n❌ SHARE CREATION FAILED: {str(e)}")
            self.log_output(self.encrypt_output, "=" * 50)
            
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
            # Clear the output first
            self.decrypt_output.delete(1.0, tk.END)
            
            self.log_output(self.decrypt_output, "🔓 STARTING DECRYPTION PROCESS...")
            self.log_output(self.decrypt_output, "=" * 80)
            self.log_output(self.decrypt_output, f"📁 Processing {len(image_paths)} stego images...")
            self.log_output(self.decrypt_output, f"🔑 Master password length: {len(master_password)} characters")
            self.log_output(self.decrypt_output, "=" * 80)
            
            # Extract share payloads
            parsed_shares = []
            for i, path in enumerate(image_paths, 1):
                self.log_output(self.decrypt_output, f"\n📁 IMAGE {i}/{len(image_paths)}: {os.path.basename(path)}")
                self.log_output(self.decrypt_output, f"🔍 Extracting data from stego image...")
                
                payload = extract_data_from_image(path)
                self.log_output(self.decrypt_output, f"📦 Extracted payload size: {len(payload)} bytes")
                
                meta = self._parse_share_payload(payload)
                parsed_shares.append(meta)
                self.log_output(self.decrypt_output, f"✅ Found share {meta['index']}/{meta['total']} (threshold={meta['threshold']})")
                self.log_output(self.decrypt_output, f"🔸 Share size: {meta['share_len']} bytes")
                self.log_output(self.decrypt_output, f"🔸 Packaged cipher size: {meta['packaged_cipher_len']} bytes")
                
            # Validate shares
            if len(parsed_shares) < 2:
                self.log_output(self.decrypt_output, "\n❌ NOT ENOUGH VALID SHARES FOUND")
                self.log_output(self.decrypt_output, "=" * 80)
                return
                
            # Check compatibility
            self.log_output(self.decrypt_output, "\n🔍 VALIDATING SHARE COMPATIBILITY...")
            vs = {s['version'] for s in parsed_shares}
            totals = {s['total'] for s in parsed_shares}
            thresholds = {s['threshold'] for s in parsed_shares}
            pkg_hashes = {s['packaged_cipher'] for s in parsed_shares}
            
            if len(vs) != 1 or len(totals) != 1 or len(thresholds) != 1 or len(pkg_hashes) != 1:
                self.log_output(self.decrypt_output, "❌ SELECTED SHARES DO NOT MATCH")
                self.log_output(self.decrypt_output, "=" * 80)
                return
                
            threshold = parsed_shares[0]['threshold']
            if len(parsed_shares) < threshold:
                self.log_output(self.decrypt_output, f"❌ NEED AT LEAST {threshold} SHARES")
                self.log_output(self.decrypt_output, "=" * 80)
                return
                
            self.log_output(self.decrypt_output, "✅ All shares are compatible!")
            self.log_output(self.decrypt_output, f"📊 Using {len(parsed_shares)} shares (threshold: {threshold})")
                
            # Recover ephemeral key
            self.log_output(self.decrypt_output, "\n🔑 RECOVERING EPHEMERAL KEY FROM SHARES...")
            share_bytes_list = [s['share_bytes'] for s in parsed_shares[:threshold]]
            packaged_cipher = parsed_shares[0]['packaged_cipher']
            
            recovered_k2 = recover_bytes_from_shares(share_bytes_list)
            if len(recovered_k2) < 16:
                recovered_k2 = (b'\x00' * (16 - len(recovered_k2))) + recovered_k2
            elif len(recovered_k2) > 16:
                recovered_k2 = recovered_k2[-16:]
                
            self.log_output(self.decrypt_output, f"✅ Ephemeral key recovered: {len(recovered_k2)} bytes")
                
            # Decrypt packaged cipher
            self.log_output(self.decrypt_output, "\n📦 DECRYPTING PACKAGED DATA...")
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
            aes = AESGCM(recovered_k2)
            nonce2 = packaged_cipher[:12]
            ct_and_tag = packaged_cipher[12:]
            binary_blob = aes.decrypt(nonce2, ct_and_tag, None)
            
            self.log_output(self.decrypt_output, f"✅ Packaged data decrypted: {len(binary_blob)} bytes")
            
            # Parse binary blob
            salt = binary_blob[:16]
            nonce = binary_blob[16:28]
            ciphertext_with_tag = binary_blob[28:]
            
            self.log_output(self.decrypt_output, f"🔸 Salt: {len(salt)} bytes")
            self.log_output(self.decrypt_output, f"🔸 Nonce: {len(nonce)} bytes")
            self.log_output(self.decrypt_output, f"🔸 Ciphertext+Tag: {len(ciphertext_with_tag)} bytes")
            
            # Decrypt with master password
            self.log_output(self.decrypt_output, "\n🔐 DECRYPTING WITH MASTER PASSWORD...")
            plaintext = decrypt_password_aes_gcm(salt, nonce, ciphertext_with_tag, master_password)
            
            # ULTRA PROMINENT SUCCESS MESSAGE
            self.log_output(self.decrypt_output, "\n" + "🎉" * 20)
            self.log_output(self.decrypt_output, "🎉 DECRYPTION SUCCESSFUL! 🎉")
            self.log_output(self.decrypt_output, "🎉" * 20)
            self.log_output(self.decrypt_output, "=" * 80)
            self.log_output(self.decrypt_output, "🔑 YOUR DECRYPTED PASSWORD IS:")
            self.log_output(self.decrypt_output, "=" * 80)
            self.log_output(self.decrypt_output, f"📝 {plaintext}")
            self.log_output(self.decrypt_output, "=" * 80)
            self.log_output(self.decrypt_output, f"📏 Password length: {len(plaintext)} characters")
            self.log_output(self.decrypt_output, "=" * 80)
            self.log_output(self.decrypt_output, "✅ SUCCESS! You can now use your password!")
            self.log_output(self.decrypt_output, "=" * 80)
            
        except Exception as e:
            self.log_output(self.decrypt_output, f"\n❌ DECRYPTION FAILED: {str(e)}")
            self.log_output(self.decrypt_output, "=" * 80)
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
            self.log_output(self.manual_output, "🔓 STARTING MANUAL DECRYPTION...")
            self.log_output(self.manual_output, "=" * 50)
            self.log_output(self.manual_output, f"📁 File: {os.path.basename(file_path)}")
            self.log_output(self.manual_output, f"🔑 Master password length: {len(master_password)} characters")
            
            # Read binary file
            self.log_output(self.manual_output, "\n📖 Reading binary file...")
            with open(file_path, "rb") as f:
                binary_blob = f.read()
                
            self.log_output(self.manual_output, f"📦 File size: {len(binary_blob)} bytes")
                
            if len(binary_blob) < 28:
                self.log_output(self.manual_output, "❌ FILE TOO SMALL TO BE VALID")
                self.log_output(self.manual_output, "=" * 50)
                return
                
            # Parse binary blob
            self.log_output(self.manual_output, "\n🔍 PARSING BINARY DATA...")
            salt = binary_blob[:16]
            nonce = binary_blob[16:28]
            ciphertext_with_tag = binary_blob[28:]
            
            self.log_output(self.manual_output, f"🔸 Salt: {len(salt)} bytes")
            self.log_output(self.manual_output, f"🔸 Nonce: {len(nonce)} bytes")
            self.log_output(self.manual_output, f"🔸 Ciphertext+Tag: {len(ciphertext_with_tag)} bytes")
            
            # Decrypt
            self.log_output(self.manual_output, "\n🔐 DECRYPTING WITH MASTER PASSWORD...")
            plaintext = decrypt_password_aes_gcm(salt, nonce, ciphertext_with_tag, master_password)
            
            self.log_output(self.manual_output, "\n🎉 MANUAL DECRYPTION SUCCESSFUL!")
            self.log_output(self.manual_output, "=" * 50)
            self.log_output(self.manual_output, "🔑 DECRYPTED PASSWORD:")
            self.log_output(self.manual_output, f"📝 {plaintext}")
            self.log_output(self.manual_output, f"📏 Password length: {len(plaintext)} characters")
            self.log_output(self.manual_output, "=" * 50)
            
        except Exception as e:
            self.log_output(self.manual_output, f"\n❌ MANUAL DECRYPTION FAILED: {str(e)}")
            self.log_output(self.manual_output, "=" * 50)

def main():
    """Main function to run the GUI"""
    root = tk.Tk()
    app = ModernFracturedKeysGUI(root)
    
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
