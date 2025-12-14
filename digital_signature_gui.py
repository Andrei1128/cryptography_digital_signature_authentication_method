import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
from digital_signature_auth import DigitalSignatureAuth
from cryptography.hazmat.primitives.serialization import load_pem_public_key
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
        ttk.Radiobutton(mode_frame, text="Multi-Sign Files", variable=self.mode_var,
                       value="multisig", command=self.toggle_mode).grid(row=0, column=2, padx=20, sticky="w")

        algorithm_frame = ttk.LabelFrame(main_frame, text="Algorithm Settings", padding="10")
        algorithm_frame.grid(row=2, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=10)

        ttk.Label(algorithm_frame, text="Key Algorithm:").grid(row=0, column=0, sticky="w", padx=5)
        self.key_algorithm_var = tk.StringVar(value="RSA")
        key_algo_combo = ttk.Combobox(algorithm_frame, textvariable=self.key_algorithm_var,
                                       values=["RSA", "ECDSA"], state="readonly", width=15)
        key_algo_combo.grid(row=0, column=1, sticky="w", padx=5)
        key_algo_combo.bind("<<ComboboxSelected>>", self.on_algorithm_changed)

        ttk.Label(algorithm_frame, text="Hash Algorithm:").grid(row=0, column=2, sticky="w", padx=5)
        self.hash_algorithm_var = tk.StringVar(value="SHA256")
        hash_algo_combo = ttk.Combobox(algorithm_frame, textvariable=self.hash_algorithm_var,
                                        values=["SHA256", "SHA512", "SHA3_256"], state="readonly", width=15)
        hash_algo_combo.grid(row=0, column=3, sticky="w", padx=5)
        hash_algo_combo.bind("<<ComboboxSelected>>", self.on_algorithm_changed)

        self.metadata_frame = ttk.LabelFrame(main_frame, text="Signer Information (Industry Standard - * = Required)", padding="10")
        self.metadata_frame.grid(row=3, column=0, columnspan=2, sticky=(tk.W, tk.E), pady=10)

        ttk.Label(self.metadata_frame, text="Signer Name: *").grid(row=0, column=0, sticky="w", padx=5)
        self.signer_name = tk.StringVar()
        ttk.Entry(self.metadata_frame, textvariable=self.signer_name, width=30).grid(row=0, column=1, padx=5, pady=2)

        ttk.Label(self.metadata_frame, text="Organization: *").grid(row=1, column=0, sticky="w", padx=5)
        self.organization = tk.StringVar()
        ttk.Entry(self.metadata_frame, textvariable=self.organization, width=30).grid(row=1, column=1, padx=5, pady=2)

        ttk.Label(self.metadata_frame, text="Email: *").grid(row=2, column=0, sticky="w", padx=5)
        self.email = tk.StringVar()
        ttk.Entry(self.metadata_frame, textvariable=self.email, width=30).grid(row=2, column=1, padx=5, pady=2)

        ttk.Label(self.metadata_frame, text="Reason: *").grid(row=0, column=2, sticky="w", padx=5)
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

    def validate_required_fields(self):
        """Validate that all required signer information is provided (Industry Standard)"""
        required_fields = {
            'Signer Name': self.signer_name.get().strip(),
            'Organization': self.organization.get().strip(),
            'Email': self.email.get().strip(),
            'Reason': self.reason.get().strip()
        }
        
        missing_fields = [name for name, value in required_fields.items() if not value]
        
        if missing_fields:
            error_msg = f"The following required fields are missing:\n\n" + "\n".join(f"• {field}" for field in missing_fields)
            error_msg += "\n\nIndustry Standard: Signer information must be complete for accountability and audit trail purposes."
            messagebox.showerror("Missing Required Fields", error_msg)
            self.status_var.set(f"Error: Missing required fields: {', '.join(missing_fields)}")
            return False
        
        return True

    def generate_keys(self):
        try:
            key_algorithm = self.key_algorithm_var.get()
            hash_algorithm = self.hash_algorithm_var.get()
            
            self.auth.set_algorithm(key_algorithm)
            self.auth.set_hash_algorithm(hash_algorithm)
            self.auth.generate_key_pair()
            
            self.status_var.set(f"New key pair generated successfully (Algorithm: {key_algorithm}, Hash: {hash_algorithm})")
            messagebox.showinfo("Success", f"New key pair generated successfully\n\nKey Algorithm: {key_algorithm}\nHash Algorithm: {hash_algorithm}")
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
            
            detected_algo = self.auth.algorithm
            self.key_algorithm_var.set(detected_algo)
            
            security_info = self.auth.validate_algorithm_security()
            recommendations = self.auth.get_algorithm_recommendations()
            
            message = f"Keys loaded successfully!\n\n"
            message += f"Auto-detected Algorithm: {detected_algo}\n"
            message += f"Security Level: {security_info['strength']}\n\n"
            message += "Recommendations:\n"
            for rec in recommendations:
                message += f"✓ {rec}\n"
            
            self.status_var.set(f"Keys loaded: {detected_algo} detected automatically")
            messagebox.showinfo("Success", message)
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
            self.sign_button.config(text="Sign Message")
            self.verify_button.config(text="Verify Signature")
        else:
            self.metadata_frame.grid()
            self.message_frame.grid_remove()
            self.signature_frame.grid_remove()
            if mode == "multisig":
                self.sign_button.config(text="Add Signature")
                self.verify_button.config(text="Verify All Signatures")
            else:
                self.sign_button.config(text="Sign File")
                self.verify_button.config(text="Verify File Signature")

    def on_algorithm_changed(self, event=None):
        """Handle algorithm selection changes"""
        key_algorithm = self.key_algorithm_var.get()
        hash_algorithm = self.hash_algorithm_var.get()
        self.auth.set_algorithm(key_algorithm)
        self.auth.set_hash_algorithm(hash_algorithm)
        self.status_var.set(f"Algorithm changed: {key_algorithm} with {hash_algorithm}")

    def sign_action(self):
        mode = self.mode_var.get()
        if mode == "message":
            self.sign_message()
        elif mode == "multisig":
            self.add_multisig_signature()
        else:
            self.sign_file()

    def verify_action(self):
        mode = self.mode_var.get()
        if mode == "message":
            self.verify_signature()
        elif mode == "multisig":
            self.verify_multisig()
        else:
            self.verify_file_signature()

    def sign_file(self):
        try:
            if not self.validate_required_fields():
                return
            
            file_path = filedialog.askopenfilename(
                title="Select File to Sign",
                filetypes=[("All files", "*.*")]
            )
            if not file_path:
                return

            metadata = {
                'signer_name': self.signer_name.get().strip(),
                'organization': self.organization.get().strip(),
                'email': self.email.get().strip(),
                'reason': self.reason.get().strip(),
                'location': self.location.get().strip()
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
            
            algo_info = self.auth.detect_signature_algorithms(signature_data)
            detected_key_algo = algo_info['key_algorithm']
            detected_hash_algo = algo_info['hash_algorithm']
            security_info = algo_info['security_info']
            
            self.key_algorithm_var.set(detected_key_algo)
            self.hash_algorithm_var.set(detected_hash_algo)
            self.auth.set_algorithm(detected_key_algo)
            self.auth.set_hash_algorithm(detected_hash_algo)
            
            is_valid = self.auth.verify_file_signature(file_path, signature_data)

            if is_valid:
                self.status_var.set("File signature is valid")
                details = f"✓ File signature is VALID\n\n"
                details += f"File: {signature_data['file_name']}\n"
                details += f"Signed: {signature_data['timestamp']}\n"
                details += f"\n📋 Signature Algorithms (Auto-detected):\n"
                details += f"  • Key Algorithm: {detected_key_algo}\n"
                details += f"  • Hash Algorithm: {detected_hash_algo}\n"
                details += f"  • Security: {security_info['strength']}\n"
                
                if signature_data.get('signer_name'):
                    details += f"\n👤 Signer: {signature_data['signer_name']}"
                if signature_data.get('organization'):
                    details += f"\n🏢 Organization: {signature_data['organization']}"
                if signature_data.get('reason'):
                    details += f"\n📝 Reason: {signature_data['reason']}"
                
                messagebox.showinfo("Success", details)
            else:
                self.status_var.set("File signature is invalid or file has been modified")
                details = f"❌ File signature is INVALID or file has been modified\n\n"
                details += f"Detected Algorithms:\n"
                details += f"  • Key Algorithm: {detected_key_algo}\n"
                details += f"  • Hash Algorithm: {detected_hash_algo}\n"
                details += f"  • Security: {security_info['strength']}\n"
                messagebox.showwarning("Warning", details)
        except Exception as e:
            self.status_var.set(f"Error verifying file signature: {str(e)}")
            messagebox.showerror("Error", f"Failed to verify file signature: {str(e)}")

    def add_multisig_signature(self):
        """Add a signature to a multi-signature document (industry-correct flow)"""
        try:
            import json

            if not self.validate_required_fields():
                return

            file_path = filedialog.askopenfilename(
                title="Select File to Multi-Sign",
                filetypes=[("All files", "*.*")]
            )
            if not file_path:
                return

            multisig_path = filedialog.askopenfilename(
                title="Load Existing Multi-Signature File (Cancel = Create New)",
                filetypes=[("JSON files", "*.json")]
            )

            if multisig_path:
                try:
                    with open(multisig_path, "r") as f:
                        multisig_data = json.load(f)
                except Exception:
                    messagebox.showerror("Error", "Invalid multisig file format")
                    return
            else:
                metadata = {
                    "signer_name": self.signer_name.get().strip(),
                    "organization": self.organization.get().strip(),
                    "email": self.email.get().strip(),
                    "reason": self.reason.get().strip(),
                    "location": self.location.get().strip()
                }
                multisig_data = self.auth.create_multisig_document(file_path, metadata)

            signer_name = self.signer_name.get().strip()
            signature_metadata = {
                "organization": self.organization.get().strip(),
                "email": self.email.get().strip(),
                "reason": self.reason.get().strip(),
                "location": self.location.get().strip()
            }

            multisig_data = self.auth.add_signature_to_document(
                multisig_data,
                file_path,
                signer_name,
                signature_metadata
            )

            save_path = filedialog.asksaveasfilename(
                title="Save Multi-Signature Data",
                defaultextension=".json",
                filetypes=[("JSON files", "*.json"), ("All files", "*.*")]
            )
            if not save_path:
                return

            self.auth.save_signature_data(multisig_data, save_path)

            if file_path.lower().endswith(".pdf"):
                try:
                    pdf_out = filedialog.asksaveasfilename(
                        title="Save PDF with Visual Signature",
                        defaultextension=".pdf",
                        filetypes=[("PDF files", "*.pdf")]
                    )
                    if pdf_out:
                        self.auth.render_all_pdf_signatures(
                            file_path,
                            pdf_out,
                            multisig_data
                        )
                except Exception:
                    pass

            self.status_var.set(f"Signature added by {signer_name}")
            messagebox.showinfo(
                "Success",
                f"Signature added successfully!\n\n"
                f"Signer: {signer_name}\n"
                f"Total signatures: {len(multisig_data.get('signatures', []))}\n\n"
                f"Saved to:\n{save_path}"
            )

        except Exception as e:
            self.status_var.set(f"Error adding signature: {str(e)}")
            messagebox.showerror("Error", f"Failed to add signature: {str(e)}")



    def verify_multisig(self):
        """Verify all signatures against the original file (industry-correct)"""
        try:
            import json
            from cryptography.hazmat.primitives.serialization import load_pem_public_key

            file_path = filedialog.askopenfilename(
                title="Select Original File to Verify",
                filetypes=[("All files", "*.*")]
            )
            if not file_path:
                return

            multisig_path = filedialog.askopenfilename(
                title="Select Multi-Signature Data File",
                filetypes=[("JSON files", "*.json")]
            )
            if not multisig_path:
                return

            with open(multisig_path, "r") as f:
                multisig_data = json.load(f)

            public_keys = {}
            for sig in multisig_data.get("signatures", []):
                signer = sig.get("signer_name", "Unknown")

                pub_key_path = filedialog.askopenfilename(
                    title=f"Select PUBLIC KEY for signer: {signer}",
                    filetypes=[("PEM files", "*.pem")]
                )
                if not pub_key_path:
                    return

                with open(pub_key_path, "rb") as pk:
                    public_keys[signer] = load_pem_public_key(pk.read())

            results = self.auth.verify_multisig_document(
                file_path,
                multisig_data,
                public_keys
            )

            if not results.get("file_valid"):
                messagebox.showerror("Verification Failed", results.get("message"))
                return

            report = "MULTI-SIGNATURE VERIFICATION RESULTS\n\n"
            for signer, res in results["signatures"].items():
                status = "VALID ✅" if res["valid"] else "INVALID ❌"
                report += f"{signer}: {status}\n"

            messagebox.showinfo("Verification Results", report)
            self.status_var.set("Multi-signature verification completed")

        except Exception as e:
            self.status_var.set(f"Error verifying multisig: {str(e)}")
            messagebox.showerror("Error", f"Verification failed: {str(e)}")


def main():
    root = tk.Tk()
    app = DigitalSignatureGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()