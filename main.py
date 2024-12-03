import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import base64
from sha_hash import generate_sha256, generate_sha512
from aes_cipher import AESCipher
from rsa_cipher import RSACipher

class CryptoGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Cryptography Tool")
        self.root.geometry("800x600")
        
        # Initialize encryption objects
        self.aes = AESCipher()
        self.rsa = RSACipher()
        self.current_iv = None
        
        # Create notebook for tabs
        self.notebook = ttk.Notebook(root)
        self.notebook.pack(expand=True, fill='both', padx=10, pady=5)
        
        # Create tabs
        self.create_hash_tab()
        self.create_aes_tab()
        self.create_rsa_tab()
        
    def create_hash_tab(self):
        hash_frame = ttk.Frame(self.notebook)
        self.notebook.add(hash_frame, text='SHA Hashing')
        
        # Input
        ttk.Label(hash_frame, text="Input Text:").pack(pady=5)
        self.hash_input = scrolledtext.ScrolledText(hash_frame, height=4)
        self.hash_input.pack(padx=5, pady=5, fill=tk.X)
        
        # Hash type selection
        self.hash_type = tk.StringVar(value="SHA-256")
        ttk.Radiobutton(hash_frame, text="SHA-256", variable=self.hash_type, 
                       value="SHA-256").pack()
        ttk.Radiobutton(hash_frame, text="SHA-512", variable=self.hash_type, 
                       value="SHA-512").pack()
        
        # Generate hash button
        ttk.Button(hash_frame, text="Generate Hash", 
                  command=self.generate_hash).pack(pady=10)
        
        # Output
        ttk.Label(hash_frame, text="Hash Output:").pack(pady=5)
        self.hash_output = scrolledtext.ScrolledText(hash_frame, height=4)
        self.hash_output.pack(padx=5, pady=5, fill=tk.X)
        
    def create_aes_tab(self):
        aes_frame = ttk.Frame(self.notebook)
        self.notebook.add(aes_frame, text='AES Encryption')
        
        # Input
        ttk.Label(aes_frame, text="Input Text:").pack(pady=5)
        self.aes_input = scrolledtext.ScrolledText(aes_frame, height=4)
        self.aes_input.pack(padx=5, pady=5, fill=tk.X)
        
        # Buttons frame
        btn_frame = ttk.Frame(aes_frame)
        btn_frame.pack(pady=10)
        
        ttk.Button(btn_frame, text="Encrypt", 
                  command=self.aes_encrypt).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Decrypt", 
                  command=self.aes_decrypt).pack(side=tk.LEFT, padx=5)
        
        # Output
        ttk.Label(aes_frame, text="Output:").pack(pady=5)
        self.aes_output = scrolledtext.ScrolledText(aes_frame, height=4)
        self.aes_output.pack(padx=5, pady=5, fill=tk.X)
        
    def create_rsa_tab(self):
        rsa_frame = ttk.Frame(self.notebook)
        self.notebook.add(rsa_frame, text='RSA Encryption')
        
        # Input
        ttk.Label(rsa_frame, text="Input Text:").pack(pady=5)
        self.rsa_input = scrolledtext.ScrolledText(rsa_frame, height=4)
        self.rsa_input.pack(padx=5, pady=5, fill=tk.X)
        
        # Buttons frame
        btn_frame = ttk.Frame(rsa_frame)
        btn_frame.pack(pady=10)
        
        ttk.Button(btn_frame, text="Encrypt", 
                  command=self.rsa_encrypt).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Decrypt", 
                  command=self.rsa_decrypt).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Sign", 
                  command=self.rsa_sign).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Verify", 
                  command=self.rsa_verify).pack(side=tk.LEFT, padx=5)
        
        # Output
        ttk.Label(rsa_frame, text="Output:").pack(pady=5)
        self.rsa_output = scrolledtext.ScrolledText(rsa_frame, height=4)
        self.rsa_output.pack(padx=5, pady=5, fill=tk.X)
        
    def generate_hash(self):
        try:
            text = self.hash_input.get("1.0", tk.END).strip()
            if not text:
                messagebox.showwarning("Warning", "Please enter text to hash")
                return
                
            if self.hash_type.get() == "SHA-256":
                hash_value = generate_sha256(text)
            else:
                hash_value = generate_sha512(text)
                
            self.hash_output.delete("1.0", tk.END)
            self.hash_output.insert("1.0", hash_value)
        except Exception as e:
            messagebox.showerror("Error", str(e))
            
    def aes_encrypt(self):
        try:
            text = self.aes_input.get("1.0", tk.END).strip()
            if not text:
                messagebox.showwarning("Warning", "Please enter text to encrypt")
                return
                
            encrypted_data, iv = self.aes.encrypt(text)
            self.current_iv = iv  # Store IV for decryption
            
            self.aes_output.delete("1.0", tk.END)
            self.aes_output.insert("1.0", encrypted_data)
        except Exception as e:
            messagebox.showerror("Error", str(e))
            
    def aes_decrypt(self):
        try:
            if self.current_iv is None:
                messagebox.showwarning("Warning", "Please encrypt some data first")
                return
                
            encrypted_text = self.aes_input.get("1.0", tk.END).strip()
            if not encrypted_text:
                messagebox.showwarning("Warning", "Please enter text to decrypt")
                return
                
            decrypted_text = self.aes.decrypt(encrypted_text, self.current_iv)
            
            self.aes_output.delete("1.0", tk.END)
            self.aes_output.insert("1.0", decrypted_text)
        except Exception as e:
            messagebox.showerror("Error", str(e))
            
    def rsa_encrypt(self):
        try:
            text = self.rsa_input.get("1.0", tk.END).strip()
            if not text:
                messagebox.showwarning("Warning", "Please enter text to encrypt")
                return
                
            encrypted_data = self.rsa.encrypt(text)
            
            self.rsa_output.delete("1.0", tk.END)
            self.rsa_output.insert("1.0", encrypted_data)
        except Exception as e:
            messagebox.showerror("Error", str(e))
            
    def rsa_decrypt(self):
        try:
            encrypted_text = self.rsa_input.get("1.0", tk.END).strip()
            if not encrypted_text:
                messagebox.showwarning("Warning", "Please enter text to decrypt")
                return
                
            decrypted_text = self.rsa.decrypt(encrypted_text)
            
            self.rsa_output.delete("1.0", tk.END)
            self.rsa_output.insert("1.0", decrypted_text)
        except Exception as e:
            messagebox.showerror("Error", str(e))
            
    def rsa_sign(self):
        try:
            text = self.rsa_input.get("1.0", tk.END).strip()
            if not text:
                messagebox.showwarning("Warning", "Please enter text to sign")
                return
                
            signature = self.rsa.sign(text)
            
            self.rsa_output.delete("1.0", tk.END)
            self.rsa_output.insert("1.0", signature)
        except Exception as e:
            messagebox.showerror("Error", str(e))
            
    def rsa_verify(self):
        try:
            text = self.rsa_input.get("1.0", tk.END).strip()
            signature = self.rsa_output.get("1.0", tk.END).strip()
            
            if not text or not signature:
                messagebox.showwarning("Warning", 
                                     "Please enter both text and signature")
                return
                
            is_valid = self.rsa.verify(text, signature)
            messagebox.showinfo("Verification Result", 
                              "Signature is valid" if is_valid else "Invalid signature")
        except Exception as e:
            messagebox.showerror("Error", str(e))

if __name__ == "__main__":
    root = tk.Tk()
    app = CryptoGUI(root)
    root.mainloop()
