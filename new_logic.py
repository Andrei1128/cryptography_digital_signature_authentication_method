import os
import hashlib
import tkinter as tk
from tkinter import filedialog, messagebox
from ecdsa import SigningKey, SECP256k1, VerifyingKey
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
import base64
import secrets
import json
import datetime
from PyPDF2 import PdfReader, PdfWriter
from reportlab.pdfgen import canvas
from reportlab.lib.pagesizes import letter
from io import BytesIO

def generate_password_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return base64.urlsafe_b64encode(kdf.derive(password.encode()))

def encrypt_and_save_keys(password: str, folder: str):
    if not os.path.exists(folder):
        os.makedirs(folder)

    sk = SigningKey.generate(curve=SECP256k1)
    vk = sk.get_verifying_key()

    with open(os.path.join(folder, "public_key.pem"), "wb") as f:
        f.write(vk.to_pem())

    salt = os.urandom(16)
    key = generate_password_key(password, salt)
    fernet = Fernet(key)
    encrypted_private_key = fernet.encrypt(sk.to_pem())

    with open(os.path.join(folder, "private_key.enc"), "wb") as f:
        f.write(salt + encrypted_private_key)

    return True

def load_private_key(path: str, password: str) -> SigningKey:
    with open(path, "rb") as f:
        data = f.read()
    salt = data[:16]
    encrypted = data[16:]
    key = generate_password_key(password, salt)
    fernet = Fernet(key)
    return SigningKey.from_pem(fernet.decrypt(encrypted))

def load_public_key(path: str) -> VerifyingKey:
    with open(path, "rb") as f:
        return VerifyingKey.from_pem(f.read())

def sign_file(sk: SigningKey, filepath: str) -> bytes:
    with open(filepath, "rb") as f:
        content = f.read()
    hashed = hashlib.sha256(content).digest()
    return sk.sign(hashed)

def verify_signature(vk: VerifyingKey, filepath: str, signature_path: str) -> bool:
    with open(filepath, "rb") as f:
        content = f.read()
    hashed = hashlib.sha256(content).digest()
    with open(signature_path, "rb") as sf:
        signature = sf.read()
    try:
        return vk.verify(signature, hashed)
    except:
        return False

def sign_challenge(sk: SigningKey, challenge: bytes) -> bytes:
    return sk.sign(hashlib.sha256(challenge).digest())

def verify_challenge(vk: VerifyingKey, challenge: bytes, signature: bytes) -> bool:
    try:
        return vk.verify(signature, hashlib.sha256(challenge).digest())
    except:
        return False

def add_visual_signature_to_pdf(input_path: str, output_path: str, name: str, timestamp: str):
    mesaj = f"Semnat digital cu ECDSA de catre {name} la data de {timestamp}."
    packet = BytesIO()
    can = canvas.Canvas(packet, pagesize=letter)
    can.setFont("Helvetica", 10)
    can.drawString(50, 40, mesaj)
    can.save()
    packet.seek(0)

    existing_pdf = PdfReader(input_path)
    overlay_pdf = PdfReader(packet)
    output_pdf = PdfWriter()

    for i in range(len(existing_pdf.pages)):
        page = existing_pdf.pages[i]
        if i == len(existing_pdf.pages) - 1:
            page.merge_page(overlay_pdf.pages[0])
        output_pdf.add_page(page)

    with open(output_path, "wb") as f:
        output_pdf.write(f)

def export_contract_signature(contract_path: str, sk: SigningKey, save_path: str, user_name: str):
    with open(contract_path, "rb") as f:
        contract_data = f.read()
    hash_doc = hashlib.sha256(contract_data).hexdigest()
    signature = sk.sign(hashlib.sha256(contract_data).digest())
    export_data = {
        "document": os.path.basename(contract_path),
        "semnat_de": user_name,
        "data": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "hash_document": hash_doc,
        "semnatura": signature.hex(),
        "cheie_publica": sk.get_verifying_key().to_pem().decode()
    }
    with open(save_path, "w") as out_file:
        json.dump(export_data, out_file, indent=4)

def verify_contract_signature(contract_path: str, signature_json_path: str) -> bool:
    try:
        with open(contract_path, "rb") as f:
            contract_data = f.read()
        with open(signature_json_path, "r") as f:
            sig_data = json.load(f)
        vk = VerifyingKey.from_pem(sig_data["cheie_publica"].encode())
        expected_hash = hashlib.sha256(contract_data).hexdigest()
        if expected_hash != sig_data["hash_document"]:
            return False
        return vk.verify(bytes.fromhex(sig_data["semnatura"]), hashlib.sha256(contract_data).digest())
    except:
        return False

app = tk.Tk()
app.title("Semnatura Digitala ECDSA - Autentificare & Contracte")
app.geometry("600x600")

frame = tk.Frame(app)
frame.pack(pady=20)

status = tk.Label(app, text="", fg="blue")
status.pack()

challenge_display = tk.Label(app, text="Challenge: -", fg="black")
challenge_display.pack()

def gui_generate_keys():
    folder = filedialog.askdirectory(title="Selecteaza folder pentru salvare chei")
    if not folder:
        return
    password = password_entry.get()
    if not password:
        messagebox.showerror("Eroare", "Introduceti o parola pentru criptare.")
        return
    encrypt_and_save_keys(password, folder)
    status.config(text=f"Cheile au fost salvate in: {folder}")

def gui_sign_file():
    private_path = filedialog.askopenfilename(title="Selecteaza cheia privata criptata")
    file_to_sign = filedialog.askopenfilename(title="Selecteaza fisierul de semnat")
    if not private_path or not file_to_sign:
        return
    password = password_entry.get()
    try:
        sk = load_private_key(private_path, password)
        signature = sign_file(sk, file_to_sign)
        save_path = filedialog.asksaveasfilename(defaultextension=".bin", title="Salveaza semnatura")
        if save_path:
            with open(save_path, "wb") as f:
                f.write(signature)
            status.config(text=f"Fisierul a fost semnat. Semnatura salvata in: {save_path}")
    except Exception as e:
        messagebox.showerror("Eroare", f"Eroare la semnare: {str(e)}")

def gui_verify_signature():
    public_path = filedialog.askopenfilename(title="Selecteaza cheia publica")
    file_to_verify = filedialog.askopenfilename(title="Selecteaza fisierul original")
    signature_path = filedialog.askopenfilename(title="Selecteaza fisierul semnatura")
    if not public_path or not file_to_verify or not signature_path:
        return
    try:
        vk = load_public_key(public_path)
        valid = verify_signature(vk, file_to_verify, signature_path)
        if valid:
            status.config(text="Semnatura este VALIDa.", fg="green")
        else:
            status.config(text="Semnatura este INVALIDa sau fisierul a fost modificat.", fg="red")
    except Exception as e:
        messagebox.showerror("Eroare", f"Eroare la verificare: {str(e)}")

def gui_authenticate():
    private_path = filedialog.askopenfilename(title="Selecteaza cheia privata criptata")
    public_path = filedialog.askopenfilename(title="Selecteaza cheia publica")
    if not private_path or not public_path:
        return
    password = password_entry.get()
    try:
        challenge = secrets.token_bytes(16)
        challenge_display.config(text=f"Challenge: {challenge.hex()}")
        sk = load_private_key(private_path, password)
        vk = load_public_key(public_path)
        signature = sign_challenge(sk, challenge)
        is_valid = verify_challenge(vk, challenge, signature)
        if is_valid:
            status.config(text="Autentificare reusita prin semnatura digitala.", fg="green")
        else:
            status.config(text="Autentificare esuata.", fg="red")
    except Exception as e:
        messagebox.showerror("Eroare", f"Eroare la autentificare: {str(e)}")

def gui_sign_contract():
    private_path = filedialog.askopenfilename(title="Selecteaza cheia privata criptata")
    contract_path = filedialog.askopenfilename(title="Selecteaza contractul de semnat")
    if not private_path or not contract_path:
        return
    password = password_entry.get()
    user_name = user_name_entry.get()
    if not user_name:
        messagebox.showerror("Eroare", "Introduceti numele utilizatorului.")
        return
    try:
        sk = load_private_key(private_path, password)
        json_save_path = filedialog.asksaveasfilename(title="Salveaza semnatura contractului", filetypes=[("JSON files", "*.json")])
        if json_save_path and not json_save_path.lower().endswith(".json"):
            json_save_path += ".json"

        if json_save_path:
            export_contract_signature(contract_path, sk, json_save_path, user_name)
            pdf_save_path = filedialog.asksaveasfilename(title="Salveaza contractul cu semnatura vizuala", filetypes=[("PDF files", "*.pdf")])
            if pdf_save_path and not pdf_save_path.lower().endswith(".pdf"):
                pdf_save_path += ".pdf"

            if pdf_save_path:
                add_visual_signature_to_pdf(contract_path, pdf_save_path, user_name, datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
                status.config(text=f"Contract semnat si salvat in: {pdf_save_path}\n Semnatura digitala exportata in: {json_save_path}")
    except Exception as e:
        messagebox.showerror("Eroare", f"Eroare la semnare contract: {str(e)}")

def gui_verify_contract():
    contract_path = filedialog.askopenfilename(title="Selecteaza contractul original")
    signature_json = filedialog.askopenfilename(title="Selecteaza semnatura (fisier .json)")
    if not contract_path or not signature_json:
        return
    try:
        is_valid = verify_contract_signature(contract_path, signature_json)
        if is_valid:
            status.config(text="Semnatura pe contract este VALIDa.", fg="green")
        else:
            status.config(text="Semnatura pe contract este INVALIDa.", fg="red")
    except Exception as e:
        messagebox.showerror("Eroare", f"Eroare la verificare contract: {str(e)}")

tk.Label(frame, text="Parola pentru criptare / semnare: ").grid(row=0, column=0, sticky="e")
password_entry = tk.Entry(frame, show="*", width=30)
password_entry.grid(row=0, column=1, pady=5)

tk.Label(frame, text="Nume utilizator: ").grid(row=1, column=0, sticky="e")
user_name_entry = tk.Entry(frame, width=30)
user_name_entry.grid(row=1, column=1, pady=5)

tk.Button(frame, text="1. Genereaza Chei", width=30, command=gui_generate_keys).grid(row=2, column=0, columnspan=2, pady=10)
tk.Button(frame, text="2. Semneaza Fisier", width=30, command=gui_sign_file).grid(row=3, column=0, columnspan=2, pady=10)
tk.Button(frame, text="3. Verifica Semnatura", width=30, command=gui_verify_signature).grid(row=4, column=0, columnspan=2, pady=10)
tk.Button(frame, text="4. Autentificare prin Semnatura", width=30, command=gui_authenticate).grid(row=5, column=0, columnspan=2, pady=10)
tk.Button(frame, text="5. Semneaza Contract", width=30, command=gui_sign_contract).grid(row=6, column=0, columnspan=2, pady=10)
tk.Button(frame, text="6. Verifica Semnatura Contract", width=30, command=gui_verify_contract).grid(row=7, column=0, columnspan=2, pady=10)

app.mainloop()
