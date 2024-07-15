import tkinter as tk
from tkinter import filedialog, messagebox
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
import os


def generate_key(password: str, salt: bytes) -> bytes:
    """Generate a derived key from password and salt using PBKDF2."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # 32 bytes key size for AES-256
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())


def encrypt_file(password: str, file_path: str, output_path: str, password_hint: str):
    """Encrypt a file using AES-CBC mode and store with salt, IV, password hint."""
    salt = os.urandom(16)
    key = generate_key(password, salt)
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    with open(file_path, 'rb') as f:
        data = f.read()

    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(data) + padder.finalize()
    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

    # Convert password hint to bytes and store with the encrypted data
    hint_length = len(password_hint).to_bytes(1, 'big')
    hint_bytes = password_hint.encode()

    with open(output_path, 'wb') as f:
        f.write(salt + iv + hint_length + hint_bytes + encrypted_data)


def decrypt_file(password: str, file_path: str, output_path: str):
    """Decrypt a file using AES-CBC mode and retrieve stored password hint."""
    with open(file_path, 'rb') as f:
        salt = f.read(16)
        iv = f.read(16)
        hint_length = int.from_bytes(f.read(1), 'big')
        password_hint = f.read(hint_length).decode()
        encrypted_data = f.read()

    key = generate_key(password, salt)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    try:
        padded_data = decryptor.update(encrypted_data) + decryptor.finalize()
        unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
        data = unpadder.update(padded_data) + unpadder.finalize()

        with open(output_path, 'wb') as f:
            f.write(data)
        return True, None  # Successful decryption
    except Exception:
        return False, password_hint  # Failed decryption, return password hint


class MainApp(tk.Tk):
    """Main application window for File Encryptor/Decryptor."""
    def __init__(self):
        super().__init__()
        self.title("File Encryptor/Decryptor")
        self.geometry("300x150")
        self.configure(bg="#2E2E2E")  # Set background color for the main window

        self.create_main_widgets()

    def create_main_widgets(self):
        """Create main widgets (buttons) for the main application window."""
        tk.Label(self, text="Choose an option:", bg="#2E2E2E", fg="#FFFFFF").pack(pady=10)
        tk.Button(self, text="Encrypt", command=self.open_encrypt_window, bg="#4A90E2", fg="#FFFFFF").pack(pady=5)
        tk.Button(self, text="Decrypt", command=self.open_decrypt_window, bg="#4A90E2", fg="#FFFFFF").pack(pady=5)

    def open_encrypt_window(self):
        """Open the Encrypt/Decrypt window in 'encrypt' mode."""
        self.withdraw()
        EncryptDecryptApp(self, "encrypt")

    def open_decrypt_window(self):
        """Open the Encrypt/Decrypt window in 'decrypt' mode."""
        self.withdraw()
        EncryptDecryptApp(self, "decrypt")


class EncryptDecryptApp(tk.Toplevel):
    """Window for Encrypt or Decrypt operations."""
    def __init__(self, parent, mode):
        super().__init__(parent)
        self.mode = mode
        self.title(f"File {mode.capitalize()}")
        self.geometry("700x350")  # Adjusted width to 700 pixels
        self.configure(bg="#2E2E2E")  # Set background color for the toplevel window

        self.file_path = tk.StringVar()
        self.password = tk.StringVar()
        self.folder_path = tk.StringVar()
        self.password_hint = tk.StringVar()

        self.create_widgets()

    def create_widgets(self):
        """Create widgets (labels, entries, buttons) for the Encrypt/Decrypt window."""
        tk.Label(self, text="File Path:", bg="#2E2E2E", fg="#FFFFFF").grid(row=0, column=0, padx=10, pady=10)
        tk.Entry(self, textvariable=self.file_path, width=50, bg="#404040", fg="#FFFFFF").grid(row=0, column=1, padx=10, pady=10)
        tk.Button(self, text="Browse", command=self.browse_file, bg="#4A90E2", fg="#FFFFFF").grid(row=0, column=2, padx=10, pady=10)

        tk.Label(self, text="Password (8-12 characters):", bg="#2E2E2E", fg="#FFFFFF").grid(row=1, column=0, padx=10, pady=10)
        tk.Entry(self, textvariable=self.password, show='*', width=50, bg="#404040", fg="#FFFFFF").grid(row=1, column=1, padx=10, pady=10)

        if self.mode == "encrypt":
            tk.Label(self, text="Password Hint:", bg="#2E2E2E", fg="#FFFFFF").grid(row=2, column=0, padx=10, pady=10)
            tk.Entry(self, textvariable=self.password_hint, width=50, bg="#404040", fg="#FFFFFF").grid(row=2, column=1, padx=10, pady=10)

        tk.Label(self, text="Output Folder Path:", bg="#2E2E2E", fg="#FFFFFF").grid(row=3, column=0, padx=10, pady=10)
        tk.Entry(self, textvariable=self.folder_path, width=50, bg="#404040", fg="#FFFFFF").grid(row=3, column=1, padx=10, pady=10)
        tk.Button(self, text="Browse", command=self.browse_folder, bg="#4A90E2", fg="#FFFFFF").grid(row=3, column=2, padx=10, pady=10)

        if self.mode == "encrypt":
            tk.Button(self, text="Encrypt", command=self.encrypt_file, bg="#4A90E2", fg="#FFFFFF").grid(row=4, column=1, pady=10)
        elif self.mode == "decrypt":
            tk.Button(self, text="Decrypt", command=self.decrypt_file, bg="#4A90E2", fg="#FFFFFF").grid(row=4, column=1, pady=10)

    def browse_file(self):
        """Open file dialog to browse and select a file."""
        file_path = filedialog.askopenfilename()
        self.file_path.set(file_path)

    def browse_folder(self):
        """Open folder dialog to browse and select a folder for output."""
        folder_path = filedialog.askdirectory()
        self.folder_path.set(folder_path)

    def encrypt_file(self):
        """Encrypt the selected file."""
        try:
            password = self.password.get()
            file_path = self.file_path.get()
            folder_path = self.folder_path.get()
            password_hint = self.password_hint.get()

            if not folder_path or not os.path.exists(folder_path):
                messagebox.showerror("Error", "Please select a valid output folder path.")
                return

            if not file_path or not password:
                messagebox.showerror("Error", "Please provide a valid file path and password.")
                return

            if not password_hint:
                messagebox.showerror("Error", "Please provide a password hint.")
                return

            output_path = os.path.join(folder_path, os.path.basename(file_path) + ".enc")

            if self.validate_password(password):
                encrypt_file(password, file_path, output_path, password_hint)
                messagebox.showinfo("Success", f"File encrypted to {output_path}")
                self.destroy()
                self.master.deiconify()
            else:
                messagebox.showerror("Error", "Please provide a valid password.")
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred: {e}")

    def decrypt_file(self):
        """Decrypt the selected file."""
        try:
            password = self.password.get()
            file_path = self.file_path.get()
            folder_path = self.folder_path.get()

            if not folder_path or not os.path.exists(folder_path):
                messagebox.showerror("Error", "Please select a valid output folder path.")
                return

            if not file_path or not password:
                messagebox.showerror("Error", "Please provide a valid file path and password.")
                return

            output_path = os.path.join(folder_path, os.path.basename(file_path).replace(".enc", "_decrypted"))

            if self.validate_password(password):
                success, hint = decrypt_file(password, file_path, output_path)
                if success:
                    messagebox.showinfo("Success", f"File decrypted to {output_path}")
                    self.destroy()
                    self.master.deiconify()
                else:
                    messagebox.showerror("Error", f"Wrong password. Hint: {hint}")
            else:
                messagebox.showerror("Error", "Please provide a valid password.")
        except Exception as e:
            messagebox.showerror("Error", f"An error occurred: {e}")

    def validate_password(self, password):
        """Validate the password length."""
        if 8 <= len(password) <= 12:
            return True
        messagebox.showerror("Error", "Password must be between 8 and 12 characters long.")
        return False


if __name__ == "__main__":
    app = MainApp()
    app.mainloop()
