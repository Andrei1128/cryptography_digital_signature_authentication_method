import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
from digital_signature_auth import DigitalSignatureAuth
import os

class DigitalSignatureGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Digital Signature Authentication")
        self.root.geometry("800x720")

        self.auth = DigitalSignatureAuth()

        main_frame = ttk.Frame(root, padding="20")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))

        key_frame = ttk.LabelFrame(main_frame, text="Key Management", padding="10")
        key_frame.grid(row=0, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=10)

        ttk.Button(key_frame, text="Generate New Keys", command=self.generate_keys).grid(row=0, column=0, padx=10)
        ttk.Button(key_frame, text="Save Keys", command=self.save_keys).grid(row=0, column=1, padx=10)
        ttk.Button(key_frame, text="Load Keys", command=self.load_keys).grid(row=0, column=2, padx=10)

        message_frame = ttk.LabelFrame(main_frame, text="Message", padding="10")
        message_frame.grid(row=1, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=10)

        self.message_text = scrolledtext.ScrolledText(message_frame, height=10, width=80, wrap=tk.WORD, font=('Arial', 11))
        self.message_text.grid(row=0, column=0, sticky=(tk.W, tk.E), padx=5, pady=5)

        signature_frame = ttk.LabelFrame(main_frame, text="Signature", padding="10")
        signature_frame.grid(row=2, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=10)

        self.signature_text = scrolledtext.ScrolledText(signature_frame, height=10, width=80, wrap=tk.WORD, font=('Arial', 11))
        self.signature_text.grid(row=0, column=0, sticky=(tk.W, tk.E), padx=5, pady=5)

        action_frame = ttk.Frame(main_frame)
        action_frame.grid(row=3, column=0, columnspan=2, pady=15)

        ttk.Button(action_frame, text="Sign Message", command=self.sign_message).grid(row=0, column=0, padx=10)
        ttk.Button(action_frame, text="Verify Signature", command=self.verify_signature).grid(row=0, column=1, padx=10)
        ttk.Button(action_frame, text="Clear All", command=self.clear_all).grid(row=0, column=2, padx=10)

        self.status_var = tk.StringVar()
        self.status_var.set("Ready")
        status_bar = ttk.Label(main_frame, textvariable=self.status_var, relief=tk.SUNKEN, padding=(5, 2))
        status_bar.grid(row=4, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(10, 0))

        main_frame.columnconfigure(0, weight=1)
        main_frame.columnconfigure(1, weight=1)
        message_frame.columnconfigure(0, weight=1)
        signature_frame.columnconfigure(0, weight=1)

        root.columnconfigure(0, weight=1)
        root.rowconfigure(0, weight=1)

    def generate_keys(self):
        try:
            self.auth.generate_key_pair()
            self.status_var.set("New key pair generated successfully")
            messagebox.showinfo("Success", "New key pair generated successfully")
        except Exception as e:
            self.status_var.set(f"Error generating keys: {str(e)}")
            messagebox.showerror("Error", f"Failed to generate keys: {str(e)}")

    def load_keys(self):
        try:
            private_key_path = filedialog.askopenfilename(
                title="Select Private Key",
                filetypes=[("PEM files", "*.pem"), ("All files", "*.*")]
            )
            if not private_key_path:
                return

            public_key_path = filedialog.askopenfilename(
                title="Select Public Key",
                filetypes=[("PEM files", "*.pem"), ("All files", "*.*")]
            )
            if not public_key_path:
                return

            self.auth.load_keys(private_key_path, public_key_path)
            self.status_var.set("Keys loaded successfully")
            messagebox.showinfo("Success", "Keys loaded successfully")
        except Exception as e:
            self.status_var.set(f"Error loading keys: {str(e)}")
            messagebox.showerror("Error", f"Failed to load keys: {str(e)}")

    def save_keys(self):
        try:
            private_key_path = filedialog.asksaveasfilename(
                title="Save Private Key",
                defaultextension=".pem",
                filetypes=[("PEM files", "*.pem"), ("All files", "*.*")]
            )
            if not private_key_path:
                return

            public_key_path = filedialog.asksaveasfilename(
                title="Save Public Key",
                defaultextension=".pem",
                filetypes=[("PEM files", "*.pem"), ("All files", "*.*")]
            )
            if not public_key_path:
                return

            self.auth.save_keys(private_key_path, public_key_path)
            self.status_var.set("Keys saved successfully")
            messagebox.showinfo("Success", "Keys saved successfully")
        except Exception as e:
            self.status_var.set(f"Error saving keys: {str(e)}")
            messagebox.showerror("Error", f"Failed to save keys: {str(e)}")

    def sign_message(self):
        try:
            message = self.message_text.get("1.0", tk.END).strip()
            if not message:
                messagebox.showwarning("Warning", "Please enter a message to sign")
                return

            signature = self.auth.sign_message(message)
            self.signature_text.delete("1.0", tk.END)
            self.signature_text.insert("1.0", signature)
            self.status_var.set("Message signed successfully")
        except Exception as e:
            self.status_var.set(f"Error signing message: {str(e)}")
            messagebox.showerror("Error", f"Failed to sign message: {str(e)}")

    def verify_signature(self):
        try:
            message = self.message_text.get("1.0", tk.END).strip()
            signature = self.signature_text.get("1.0", tk.END).strip()

            if not message or not signature:
                messagebox.showwarning("Warning", "Please enter both message and signature")
                return

            is_valid = self.auth.verify_signature(message, signature)
            if is_valid:
                self.status_var.set("Signature is valid")
                messagebox.showinfo("Success", "Signature is valid")
            else:
                self.status_var.set("Signature is invalid")
                messagebox.showwarning("Warning", "Signature is invalid")
        except Exception as e:
            self.status_var.set(f"Error verifying signature: {str(e)}")
            messagebox.showerror("Error", f"Failed to verify signature: {str(e)}")

    def clear_all(self):
        self.message_text.delete("1.0", tk.END)
        self.signature_text.delete("1.0", tk.END)
        self.status_var.set("Ready")

def main():
    root = tk.Tk()
    app = DigitalSignatureGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()