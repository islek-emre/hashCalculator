import hashlib
import tkinter as tk
from tkinter import filedialog, scrolledtext, messagebox

# Hash hesaplama fonksiyonu
def calculate_hash(file_path):
    try:
        # Dosyanın hash değerlerini hesapla
        with open(file_path, "rb") as f:
            file_data = f.read()
            md5_hash = hashlib.md5(file_data).hexdigest()
            sha1_hash = hashlib.sha1(file_data).hexdigest()
            sha256_hash = hashlib.sha256(file_data).hexdigest()
        
        # Sonuçları GUI'ye yazdır
        result_text.delete(1.0, tk.END)
        result_text.insert(tk.END, f"File: {file_path}\n\n")
        result_text.insert(tk.END, f"MD5    : {md5_hash}\n")
        result_text.insert(tk.END, f"SHA-1  : {sha1_hash}\n")
        result_text.insert(tk.END, f"SHA-256: {sha256_hash}\n")
        
    except Exception as e:
        messagebox.showerror("Error", f"Failed to calculate hash: {e}")

# Dosya seçimi ve hash hesaplama
def select_file():
    file_path = filedialog.askopenfilename()
    if file_path:
        calculate_hash(file_path)

# GUI kurulum
root = tk.Tk()
root.title("File Hash Calculator")

# Dosya Seçme Düğmesi
select_button = tk.Button(root, text="Select File", command=select_file)
select_button.grid(row=0, column=0, padx=10, pady=10)

# Hash sonuçlarını gösteren kaydırılabilir metin kutusu
result_text = scrolledtext.ScrolledText(root, width=60, height=10)
result_text.grid(row=1, column=0, padx=10, pady=10)

root.mainloop()
