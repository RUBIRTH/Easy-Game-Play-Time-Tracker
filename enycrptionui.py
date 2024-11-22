import hashlib
import base64
from datetime import datetime
from cryptography.fernet import Fernet
import tkinter as tk
from tkinter import messagebox, scrolledtext

# Encryption and decryption functions
def generate_key(day, secret="MySecretSeed"):
    """Generate a Fernet-compatible key."""
    combined = f"{day}:{secret}"
    key = hashlib.sha256(combined.encode()).digest()  # 32 bytes
    return base64.urlsafe_b64encode(key)  # Convert to base64 for Fernet compatibility

def encrypt_message_ui(input_text, output_box):
    """Encrypt a message and display the result in the output box."""
    day = datetime.now().strftime("%A")
    message = input_text.get("1.0", tk.END).strip()

    if not message:
        messagebox.showerror("Error", "Please enter a message to encrypt.")
        return

    # Generate key and encrypt
    key = generate_key(day)
    fernet = Fernet(key)
    combined_message = f"{day}:{message}".encode()
    encrypted_message = fernet.encrypt(combined_message).decode()

    # Display encrypted message
    output_box.delete("1.0", tk.END)
    output_box.insert(tk.END, encrypted_message)

def decrypt_message_ui(input_text, output_box):
    """Decrypt a message and display the result in the output box."""
    encrypted_message = input_text.get("1.0", tk.END).strip().encode()

    if not encrypted_message:
        messagebox.showerror("Error", "Please enter an encrypted message.")
        return

    # Get today's key
    current_day = datetime.now().strftime("%A")
    key = generate_key(current_day)
    fernet = Fernet(key)

    try:
        decrypted_message = fernet.decrypt(encrypted_message).decode()
        encrypted_day, original_message = decrypted_message.split(":", 1)

        if encrypted_day != current_day:
            messagebox.showerror("Error", f"Decryption failed: Message was encrypted on {encrypted_day}.")
            return

        # Display decrypted message
        output_box.delete("1.0", tk.END)
        output_box.insert(tk.END, original_message)

    except Exception:
        messagebox.showerror("Error", "Invalid encrypted message or key.")

# GUI setup
def create_main_window():
    """Create the main GUI window."""
    window = tk.Tk()
    window.title("Secure Encryption Tool")
    window.geometry("400x300")
    window.resizable(False, False)

    # Main menu label
    tk.Label(window, text="Secure Encryption Tool", font=("Arial", 16, "bold")).pack(pady=20)

    # Buttons for actions
    tk.Button(window, text="Encrypt Message", command=create_encrypt_window, width=20, height=2).pack(pady=10)
    tk.Button(window, text="Decrypt Message", command=create_decrypt_window, width=20, height=2).pack(pady=10)
    tk.Button(window, text="Exit", command=window.quit, width=20, height=2).pack(pady=10)

    window.mainloop()

def create_encrypt_window():
    """Create the encryption window."""
    encrypt_window = tk.Toplevel()
    encrypt_window.title("Encrypt a Message")
    encrypt_window.geometry("500x400")

    # Input message
    tk.Label(encrypt_window, text="Enter the message to encrypt:", font=("Arial", 12)).pack(pady=5)
    input_text = scrolledtext.ScrolledText(encrypt_window, wrap=tk.WORD, width=50, height=5)
    input_text.pack(pady=5)

    # Output encrypted message
    tk.Label(encrypt_window, text="Encrypted message:", font=("Arial", 12)).pack(pady=5)
    output_box = scrolledtext.ScrolledText(encrypt_window, wrap=tk.WORD, width=50, height=5)
    output_box.pack(pady=5)

    # Copy button
    def copy_to_clipboard():
        encrypted_message = output_box.get("1.0", tk.END).strip()
        if encrypted_message:
            encrypt_window.clipboard_clear()
            encrypt_window.clipboard_append(encrypted_message)
            encrypt_window.update()  # Notify the system of the clipboard change
            messagebox.showinfo("Copied", "Encrypted message copied to clipboard!")
        else:
            messagebox.showerror("Error", "No encrypted message to copy.")

    # Buttons
    tk.Button(encrypt_window, text="Encrypt", command=lambda: encrypt_message_ui(input_text, output_box), width=15).pack(pady=10)
    tk.Button(encrypt_window, text="Copy to Clipboard", command=copy_to_clipboard, width=15).pack(pady=5)

def create_decrypt_window():
    """Create the decryption window."""
    decrypt_window = tk.Toplevel()
    decrypt_window.title("Decrypt a Message")
    decrypt_window.geometry("500x400")

    # Input encrypted message
    tk.Label(decrypt_window, text="Enter the encrypted message:", font=("Arial", 12)).pack(pady=5)
    input_text = scrolledtext.ScrolledText(decrypt_window, wrap=tk.WORD, width=50, height=5)
    input_text.pack(pady=5)

    # Output decrypted message
    tk.Label(decrypt_window, text="Decrypted message:", font=("Arial", 12)).pack(pady=5)
    output_box = scrolledtext.ScrolledText(decrypt_window, wrap=tk.WORD, width=50, height=5)
    output_box.pack(pady=5)

    # Decrypt button
    tk.Button(decrypt_window, text="Decrypt", command=lambda: decrypt_message_ui(input_text, output_box), width=15).pack(pady=10)

# Run the application
if __name__ == "__main__":
    create_main_window()
