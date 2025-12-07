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

        mode_frame = ttk.LabelFrame(main_frame, text="Operation Mode", padding="10")
        mode_frame.grid(row=1, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=10)

        self.mode_var = tk.StringVar(value="message")
        ttk.Radiobutton(mode_frame, text="Sign/Verify Messages", variable=self.mode_var,
                       value="message", command=self.toggle_mode).grid(row=0, column=0, padx=20, sticky="w")
        ttk.Radiobutton(mode_frame, text="Sign/Verify Files", variable=self.mode_var,
                       value="file", command=self.toggle_mode).grid(row=0, column=1, padx=20, sticky="w")

        self.metadata_frame = ttk.LabelFrame(main_frame, text="Signer Information", padding="10")
        self.metadata_frame.grid(row=2, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=10)

        ttk.Label(self.metadata_frame, text="Signer Name:").grid(row=0, column=0, sticky="w", padx=5)
        self.signer_name = tk.StringVar()
        ttk.Entry(self.metadata_frame, textvariable=self.signer_name, width=30).grid(row=0, column=1, padx=5, pady=2)

        ttk.Label(self.metadata_frame, text="Organization:").grid(row=1, column=0, sticky="w", padx=5)
        self.organization = tk.StringVar()
        ttk.Entry(self.metadata_frame, textvariable=self.organization, width=30).grid(row=1, column=1, padx=5, pady=2)

        ttk.Label(self.metadata_frame, text="Email:").grid(row=2, column=0, sticky="w", padx=5)
        self.email = tk.StringVar()
        ttk.Entry(self.metadata_frame, textvariable=self.email, width=30).grid(row=2, column=1, padx=5, pady=2)

        ttk.Label(self.metadata_frame, text="Reason:").grid(row=0, column=2, sticky="w", padx=5)
        self.reason = tk.StringVar()
        ttk.Entry(self.metadata_frame, textvariable=self.reason, width=30).grid(row=0, column=3, padx=5, pady=2)

        ttk.Label(self.metadata_frame, text="Location:").grid(row=1, column=2, sticky="w", padx=5)
        self.location = tk.StringVar()
        ttk.Entry(self.metadata_frame, textvariable=self.location, width=30).grid(row=1, column=3, padx=5, pady=2)

        self.message_frame = ttk.LabelFrame(main_frame, text="Message", padding="10")
        self.message_frame.grid(row=3, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=10)

        self.message_text = scrolledtext.ScrolledText(self.message_frame, height=7, width=80, wrap=tk.WORD, font=('Arial', 11))
        self.message_text.grid(row=0, column=0, sticky=(tk.W, tk.E), padx=5, pady=5)

        self.signature_frame = ttk.LabelFrame(main_frame, text="Signature", padding="10")
        self.signature_frame.grid(row=4, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=10)

        self.signature_text = scrolledtext.ScrolledText(self.signature_frame, height=7, width=80, wrap=tk.WORD, font=('Arial', 11))
        self.signature_text.grid(row=0, column=0, sticky=(tk.W, tk.E), padx=5, pady=5)

        self.file_frame = ttk.LabelFrame(main_frame, text="File Operations", padding="10")
        self.file_frame.grid(row=5, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=10)

        ttk.Button(self.file_frame, text="Sign File", command=self.sign_file).grid(row=0, column=0, padx=10)
        ttk.Button(self.file_frame, text="Verify File Signature", command=self.verify_file_signature).grid(row=0, column=1, padx=10)

        self.action_frame = ttk.Frame(main_frame)
        self.action_frame.grid(row=6, column=0, columnspan=2, pady=15)

        self.sign_button = ttk.Button(self.action_frame, text="Sign", command=self.sign_action)
        self.sign_button.grid(row=0, column=0, padx=10)

        self.verify_button = ttk.Button(self.action_frame, text="Verify", command=self.verify_action)
        self.verify_button.grid(row=0, column=1, padx=10)

        ttk.Button(self.action_frame, text="Clear All", command=self.clear_all).grid(row=0, column=2, padx=10)

        self.status_var = tk.StringVar()
        self.status_var.set("Ready")
        status_bar = ttk.Label(main_frame, textvariable=self.status_var, relief=tk.SUNKEN, padding=(5, 2))
        status_bar.grid(row=7, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=(10, 0))

        main_frame.columnconfigure(0, weight=1)
        main_frame.columnconfigure(1, weight=1)
        self.message_frame.columnconfigure(0, weight=1)
        self.signature_frame.columnconfigure(0, weight=1)

        root.columnconfigure(0, weight=1)
        root.rowconfigure(0, weight=1)

        self.toggle_mode()

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

    def toggle_mode(self):
        mode = self.mode_var.get()
        if mode == "message":
            self.metadata_frame.grid_remove()
            self.message_frame.grid()
            self.signature_frame.grid()
            self.file_frame.grid_remove()
            self.sign_button.config(text="Sign Message")
            self.verify_button.config(text="Verify Signature")
        else:
            self.metadata_frame.grid()
            self.message_frame.grid_remove()
            self.signature_frame.grid_remove()
            self.file_frame.grid()
            self.sign_button.config(text="Sign File")
            self.verify_button.config(text="Verify File Signature")

    def sign_action(self):
        if self.mode_var.get() == "message":
            self.sign_message()
        else:
            self.sign_file()

    def verify_action(self):
        if self.mode_var.get() == "message":
            self.verify_signature()
        else:
            self.verify_file_signature()

    def sign_file(self):
        try:
            file_path = filedialog.askopenfilename(
                title="Select File to Sign",
                filetypes=[("All files", "*.*")]
            )
            if not file_path:
                return

            metadata = {
                'signer_name': self.signer_name.get(),
                'organization': self.organization.get(),
                'email': self.email.get(),
                'reason': self.reason.get(),
                'location': self.location.get()
            }

            signature_data = self.auth.sign_file(file_path, metadata)

            save_path = filedialog.asksaveasfilename(
                title="Save Signature Data",
                defaultextension=".json",
                filetypes=[("JSON files", "*.json"), ("All files", "*.*")]
            )
            if not save_path:
                return

            self.auth.save_signature_data(signature_data, save_path)

            if file_path.lower().endswith('.pdf') and any(metadata.values()):
                try:
                    pdf_output_path = filedialog.asksaveasfilename(
                        title="Save Signed PDF",
                        defaultextension=".pdf",
                        filetypes=[("PDF files", "*.pdf"), ("All files", "*.*")]
                    )
                    if pdf_output_path:
                        self.auth.add_pdf_signature_footer(file_path, pdf_output_path, signature_data)
                        self.status_var.set(f"File signed with PDF footer added")
                        messagebox.showinfo("Success", f"File signed with signature footer added:\n{pdf_output_path}\nSignature data saved to: {save_path}")
                    else:
                        self.status_var.set(f"File '{os.path.basename(file_path)}' signed successfully")
                        messagebox.showinfo("Success", f"File signed and signature saved to:\n{save_path}")
                except ImportError:
                    self.status_var.set(f"File signed (PDF footer requires PyPDF2 and reportlab)")
                    messagebox.showwarning("PDF Libraries Missing", f"File signed successfully but PDF footer could not be added.\nInstall PyPDF2 and reportlab for PDF support.\nSignature saved to: {save_path}")
                except Exception as pdf_error:
                    self.status_var.set(f"File signed (PDF footer failed: {str(pdf_error)})")
                    messagebox.showwarning("PDF Error", f"File signed successfully but PDF footer failed:\n{str(pdf_error)}\nSignature saved to: {save_path}")
            else:
                self.status_var.set(f"File '{os.path.basename(file_path)}' signed successfully")
                messagebox.showinfo("Success", f"File signed and signature saved to:\n{save_path}")

        except Exception as e:
            self.status_var.set(f"Error signing file: {str(e)}")
            messagebox.showerror("Error", f"Failed to sign file: {str(e)}")

    def verify_file_signature(self):
        try:
            file_path = filedialog.askopenfilename(
                title="Select Original File",
                filetypes=[("All files", "*.*")]
            )
            if not file_path:
                return

            signature_path = filedialog.askopenfilename(
                title="Select Signature Data File",
                filetypes=[("JSON files", "*.json"), ("All files", "*.*")]
            )
            if not signature_path:
                return

            signature_data = self.auth.load_signature_data(signature_path)
            is_valid = self.auth.verify_file_signature(file_path, signature_data)

            if is_valid:
                self.status_var.set("File signature is valid")
                details = f"File signature is VALID\n\nFile: {signature_data['file_name']}\nSigned: {signature_data['timestamp']}"
                if signature_data.get('signer_name'):
                    details += f"\nSigner: {signature_data['signer_name']}"
                if signature_data.get('organization'):
                    details += f"\nOrganization: {signature_data['organization']}"
                if signature_data.get('reason'):
                    details += f"\nReason: {signature_data['reason']}"
                messagebox.showinfo("Success", details)
            else:
                self.status_var.set("File signature is invalid or file has been modified")
                messagebox.showwarning("Warning", "File signature is INVALID or file has been modified")
        except Exception as e:
            self.status_var.set(f"Error verifying file signature: {str(e)}")
            messagebox.showerror("Error", f"Failed to verify file signature: {str(e)}")

def main():
    root = tk.Tk()
    app = DigitalSignatureGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()