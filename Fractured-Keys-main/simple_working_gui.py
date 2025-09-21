#!/usr/bin/env python3
"""
Fractured Keys - Simple Working GUI
A very simple, reliable GUI for the password manager
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

class SimpleWorkingGUI:
    def __init__(self, root):
        self.root = root
        self.setup_window()
        self.create_widgets()
        
    def setup_window(self):
        """Configure the main window"""
        self.root.title("Fractured Keys - Password Manager")
        self.root.geometry("700x500")
        self.root.configure(bg='white')
        
    def create_widgets(self):
        """Create all GUI widgets"""
        # Title
        title_label = tk.Label(self.root, text="Fractured Keys", 
                              font=('Arial', 18, 'bold'), 
                              bg='white', fg='blue')
        title_label.pack(pady=20)
        
        # Create notebook for tabs
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill='both', expand=True, padx=20, pady=(0, 20))
        
        # Create tabs
        self.create_encrypt_tab()
        self.create_decrypt_tab()
        self.create_manual_tab()
        
    def create_encrypt_tab(self):
        """Create encryption tab"""
        self.encrypt_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.encrypt_frame, text="Encrypt")
        
        # Password input
        tk.Label(self.encrypt_frame, text="Password to Encrypt:", 
                font=('Arial', 12)).pack(anchor='w', padx=20, pady=(20, 5))
        
        self.password_entry = tk.Entry(self.encrypt_frame, show="*", width=50)
        self.password_entry.pack(padx=20, pady=(0, 15))
        
        # Master password input
        tk.Label(self.encrypt_frame, text="Master Password:", 
                font=('Arial', 12)).pack(anchor='w', padx=20, pady=(0, 5))
        
        self.master_password_entry = tk.Entry(self.encrypt_frame, show="*", width=50)
        self.master_password_entry.pack(padx=20, pady=(0, 15))
        
        # Options
        self.use_shares_var = tk.BooleanVar(value=True)
        shares_check = tk.Checkbutton(self.encrypt_frame, 
                                     text="Split into 3 shares and embed into images", 
                                     variable=self.use_shares_var)
        shares_check.pack(anchor='w', padx=20, pady=(0, 20))
        
        # Encrypt button
        self.encrypt_btn = tk.Button(self.encrypt_frame, text="Start Encryption", 
                                    command=self.start_encryption,
                                    bg='blue', fg='white', font=('Arial', 12))
        self.encrypt_btn.pack(pady=20)
        
        # Progress bar
        self.encrypt_progress = ttk.Progressbar(self.encrypt_frame, mode='indeterminate')
        self.encrypt_progress.pack(fill='x', padx=20, pady=(0, 20))
        
        # Output area
        tk.Label(self.encrypt_frame, text="Output:", 
                font=('Arial', 12)).pack(anchor='w', padx=20, pady=(0, 5))
        
        self.encrypt_output = scrolledtext.ScrolledText(self.encrypt_frame, height=10, width=60)
        self.encrypt_output.pack(fill='both', expand=True, padx=20, pady=(0, 20))
        
    def create_decrypt_tab(self):
        """Create decryption tab"""
        self.decrypt_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.decrypt_frame, text="Decrypt")
        
        # Instructions
        tk.Label(self.decrypt_frame, text="Select at least 2 stego images:", 
                font=('Arial', 12)).pack(anchor='w', padx=20, pady=(20, 5))
        
        # Image list
        list_frame = tk.Frame(self.decrypt_frame)
        list_frame.pack(fill='x', padx=20, pady=(0, 10))
        
        self.image_listbox = tk.Listbox(list_frame, height=4)
        scrollbar = tk.Scrollbar(list_frame, orient="vertical", command=self.image_listbox.yview)
        self.image_listbox.configure(yscrollcommand=scrollbar.set)
        
        self.image_listbox.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")
        
        # Buttons
        btn_frame = tk.Frame(self.decrypt_frame)
        btn_frame.pack(fill='x', padx=20, pady=(0, 15))
        
        tk.Button(btn_frame, text="Add Image", command=self.add_image_file,
                 bg='gray', fg='white').pack(side='left', padx=(0, 10))
        
        tk.Button(btn_frame, text="Remove Selected", command=self.remove_selected_image,
                 bg='red', fg='white').pack(side='left')
        
        # Master password
        tk.Label(self.decrypt_frame, text="Master Password:", 
                font=('Arial', 12)).pack(anchor='w', padx=20, pady=(0, 5))
        
        self.decrypt_master_entry = tk.Entry(self.decrypt_frame, show="*", width=50)
        self.decrypt_master_entry.pack(padx=20, pady=(0, 15))
        
        # Decrypt button
        self.decrypt_btn = tk.Button(self.decrypt_frame, text="Start Decryption", 
                                    command=self.start_decryption,
                                    bg='green', fg='white', font=('Arial', 12))
        self.decrypt_btn.pack(pady=20)
        
        # Progress bar
        self.decrypt_progress = ttk.Progressbar(self.decrypt_frame, mode='indeterminate')
        self.decrypt_progress.pack(fill='x', padx=20, pady=(0, 20))
        
        # Output area
        tk.Label(self.decrypt_frame, text="Results:", 
                font=('Arial', 12)).pack(anchor='w', padx=20, pady=(0, 5))
        
        self.decrypt_output = scrolledtext.ScrolledText(self.decrypt_frame, height=10, width=60)
        self.decrypt_output.pack(fill='both', expand=True, padx=20, pady=(0, 20))
        
        # Store selected images
        self.selected_images = []
        
    def create_manual_tab(self):
        """Create manual decryption tab"""
        self.manual_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.manual_frame, text="Manual")
        
        # Instructions
        tk.Label(self.manual_frame, text="Select .bin file for decryption:", 
                font=('Arial', 12)).pack(anchor='w', padx=20, pady=(20, 5))
        
        # File input
        file_frame = tk.Frame(self.manual_frame)
        file_frame.pack(fill='x', padx=20, pady=(0, 15))
        
        self.manual_file_entry = tk.Entry(file_frame, width=40)
        self.manual_file_entry.pack(side='left', fill='x', expand=True, padx=(0, 10))
        
        tk.Button(file_frame, text="Browse", command=self.browse_manual_file,
                 bg='gray', fg='white').pack(side='right')
        
        # Master password
        tk.Label(self.manual_frame, text="Master Password:", 
                font=('Arial', 12)).pack(anchor='w', padx=20, pady=(0, 5))
        
        self.manual_master_entry = tk.Entry(self.manual_frame, show="*", width=50)
        self.manual_master_entry.pack(padx=20, pady=(0, 15))
        
        # Decrypt button
        self.manual_decrypt_btn = tk.Button(self.manual_frame, text="Decrypt File", 
                                            command=self.start_manual_decryption,
                                            bg='green', fg='white', font=('Arial', 12))
        self.manual_decrypt_btn.pack(pady=20)
        
        # Output area
        tk.Label(self.manual_frame, text="Results:", 
                font=('Arial', 12)).pack(anchor='w', padx=20, pady=(0, 5))
        
        self.manual_output = scrolledtext.ScrolledText(self.manual_frame, height=15, width=60)
        self.manual_output.pack(fill='both', expand=True, padx=20, pady=(0, 20))
        
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
        
        thread = threading.Thread(target=self.encrypt_worker, args=(password, master_password))
        thread.daemon = True
        thread.start()
        
    def encrypt_worker(self, password, master_password):
        """Encryption worker thread"""
        try:
            self.log_output(self.encrypt_output, "Starting encryption process...")
            
            # Encrypt the password
            self.log_output(self.encrypt_output, "Encrypting password...")
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
                self.log_output(self.encrypt_output, "\nSplitting into SSS shares...")
                self.create_shares_and_embed(binary_blob)
            else:
                # Save as binary file
                filename = "encrypted_output.bin"
                with open(filename, "wb") as f:
                    f.write(binary_blob)
                self.log_output(self.encrypt_output, f"\nBinary file saved: {filename}")
                
        except Exception as e:
            self.log_output(self.encrypt_output, f"Encryption failed: {str(e)}")
        finally:
            self.root.after(0, self.encryption_finished)
            
    def create_shares_and_embed(self, binary_blob):
        """Create shares and embed into images"""
        try:
            import os
            from cryptography.hazmat.primitives.ciphers.aead import AESGCM
            
            # Generate ephemeral key and encrypt binary blob
            self.log_output(self.encrypt_output, "Generating ephemeral key...")
            K2 = os.urandom(16)
            aes = AESGCM(K2)
            nonce2 = os.urandom(12)
            packaged_ct_and_tag = aes.encrypt(nonce2, binary_blob, None)
            packaged_cipher = nonce2 + packaged_ct_and_tag
            
            # Split K2 into shares
            n_shares = 3
            threshold = 2
            self.log_output(self.encrypt_output, f"Splitting into {n_shares} shares...")
            shares = split_bytes_into_shares(K2, n=n_shares, k=threshold)
            
            # For each share, ask user to select carrier image
            for i, share_bytes in enumerate(shares, start=1):
                self.log_output(self.encrypt_output, f"\nSelect carrier image for share {i}/{n_shares}")
                
                # Use file dialog
                file_types = [("Images", ("*.png","*.jpg","*.jpeg","*.bmp","*.tiff")), ("All files", "*.*")]
                carrier_path = filedialog.askopenfilename(
                    title=f"Select carrier image for share {i}",
                    filetypes=file_types
                )
                
                if not carrier_path:
                    self.log_output(self.encrypt_output, f"No carrier selected for share {i}. Skipping.")
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
                self.log_output(self.encrypt_output, f"Share {i} embedded into: {saved_path}")
                
            self.log_output(self.encrypt_output, "\nAll shares processed successfully!")
            self.log_output(self.encrypt_output, "Keep at least 2 of the stego images safe.")
            
        except Exception as e:
            self.log_output(self.encrypt_output, f"Share creation failed: {str(e)}")
            
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
        
        thread = threading.Thread(target=self.decrypt_worker, args=(self.selected_images, master_password))
        thread.daemon = True
        thread.start()
        
    def decrypt_worker(self, image_paths, master_password):
        """Decryption worker thread"""
        try:
            self.log_output(self.decrypt_output, "Starting decryption process...")
            
            # Extract share payloads
            parsed_shares = []
            for path in image_paths:
                self.log_output(self.decrypt_output, f"Extracting data from: {os.path.basename(path)}")
                payload = extract_data_from_image(path)
                meta = self._parse_share_payload(payload)
                parsed_shares.append(meta)
                self.log_output(self.decrypt_output, f"Found share {meta['index']}/{meta['total']}")
                
            # Validate shares
            if len(parsed_shares) < 2:
                self.log_output(self.decrypt_output, "Not enough valid shares found")
                return
                
            # Check compatibility
            vs = {s['version'] for s in parsed_shares}
            totals = {s['total'] for s in parsed_shares}
            thresholds = {s['threshold'] for s in parsed_shares}
            pkg_hashes = {s['packaged_cipher'] for s in parsed_shares}
            
            if len(vs) != 1 or len(totals) != 1 or len(thresholds) != 1 or len(pkg_hashes) != 1:
                self.log_output(self.decrypt_output, "Selected shares do not match")
                return
                
            threshold = parsed_shares[0]['threshold']
            if len(parsed_shares) < threshold:
                self.log_output(self.decrypt_output, f"Need at least {threshold} shares")
                return
                
            # Recover ephemeral key
            self.log_output(self.decrypt_output, "Recovering ephemeral key...")
            share_bytes_list = [s['share_bytes'] for s in parsed_shares[:threshold]]
            packaged_cipher = parsed_shares[0]['packaged_cipher']
            
            recovered_k2 = recover_bytes_from_shares(share_bytes_list)
            if len(recovered_k2) < 16:
                recovered_k2 = (b'\x00' * (16 - len(recovered_k2))) + recovered_k2
            elif len(recovered_k2) > 16:
                recovered_k2 = recovered_k2[-16:]
                
            # Decrypt packaged cipher
            self.log_output(self.decrypt_output, "Decrypting packaged data...")
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
            self.log_output(self.decrypt_output, "Decrypting with master password...")
            plaintext = decrypt_password_aes_gcm(salt, nonce, ciphertext_with_tag, master_password)
            
            self.log_output(self.decrypt_output, "\nDECRYPTION SUCCESSFUL!")
            self.log_output(self.decrypt_output, f"Decrypted password: {plaintext}")
            self.log_output(self.decrypt_output, f"Password length: {len(plaintext)} characters")
            
        except Exception as e:
            self.log_output(self.decrypt_output, f"Decryption failed: {str(e)}")
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
            self.log_output(self.manual_output, "Starting manual decryption...")
            
            # Read binary file
            with open(file_path, "rb") as f:
                binary_blob = f.read()
                
            if len(binary_blob) < 28:
                self.log_output(self.manual_output, "File too small to be valid")
                return
                
            # Parse binary blob
            salt = binary_blob[:16]
            nonce = binary_blob[16:28]
            ciphertext_with_tag = binary_blob[28:]
            
            # Decrypt
            self.log_output(self.manual_output, "Decrypting with master password...")
            plaintext = decrypt_password_aes_gcm(salt, nonce, ciphertext_with_tag, master_password)
            
            self.log_output(self.manual_output, "\nDECRYPTION SUCCESSFUL!")
            self.log_output(self.manual_output, f"Decrypted password: {plaintext}")
            self.log_output(self.manual_output, f"Password length: {len(plaintext)} characters")
            
        except Exception as e:
            self.log_output(self.manual_output, f"Manual decryption failed: {str(e)}")
    
    def log_output(self, text_widget, message):
        """Add message to output text widget"""
        text_widget.insert(tk.END, message + "\n")
        text_widget.see(tk.END)
        self.root.update_idletasks()

def main():
    """Main function to run the GUI"""
    root = tk.Tk()
    app = SimpleWorkingGUI(root)
    
    # Handle window closing
    def on_closing():
        if messagebox.askokcancel("Quit", "Do you want to quit Fractured Keys?"):
            root.destroy()
    
    root.protocol("WM_DELETE_WINDOW", on_closing)
    root.mainloop()

if __name__ == "__main__":
    main()
