import os
import sys
import struct
import threading
import tkinter as tk
from random import getrandbits
from tkinter import ttk, filedialog, messagebox
from PIL import Image, ImageTk
from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA256
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes

# ==== CRYPTO PARAMETERS ====
PBKDF2_ITERS = 1_000_000
SALT_SIZE    = 16
NONCE_SIZE   = 12
HMAC_SIZE    = 32
MARKER       = b'BITSHDW1'  # 8-byte signature

def resource_path(rel_path: str) -> str:
    """Get absolute path to resource, works with PyInstaller."""
    try:
        base = sys._MEIPASS
    except AttributeError:
        base = os.path.abspath(".")
    return os.path.join(base, rel_path)

def derive_keys(password: str, salt: bytes):
    km = PBKDF2(password, salt, dkLen=64, count=PBKDF2_ITERS, hmac_hash_module=SHA256)
    return km[:32], km[32:]

def bytes_to_bits(data: bytes) -> list[int]:
    bits = []
    for b in data:
        for i in range(8):
            bits.append((b >> (7 - i)) & 1)
    return bits

def bits_to_bytes(bits: list[int]) -> bytes:
    b = bytearray(len(bits) // 8)
    for i, bit in enumerate(bits):
        b[i // 8] |= bit << (7 - (i % 8))
    return bytes(b)

def embed_message(png_in: str, png_out: str, txt_in: str, password: str):
    # read plaintext
    with open(txt_in, "rb") as f:
        plaintext = f.read()

    # derive keys
    salt     = get_random_bytes(SALT_SIZE)
    aes_key, hmac_key = derive_keys(password, salt)

    # encrypt with AES-GCM
    cipher = AES.new(aes_key, AES.MODE_GCM, nonce=get_random_bytes(NONCE_SIZE))
    ct, tag = cipher.encrypt_and_digest(plaintext)

    # build payload: marker | salt | nonce | ciphertext | tag
    payload = MARKER + salt + cipher.nonce + ct + tag

    # append HMAC
    h = HMAC.new(hmac_key, digestmod=SHA256)
    h.update(payload)
    full = payload + h.digest()

    # prefix length (4 bytes BE)
    data = struct.pack(">I", len(full)) + full
    bits = bytes_to_bits(data)

    # open image
    img      = Image.open(png_in)
    w, h     = img.size
    pixels   = list(img.getdata())

    capacity = w * h * 3
    if len(bits) > capacity:
        raise ValueError("Imagem não comporta todos os dados.")

    # sequential LSB embed
    new_pixels = []
    bit_idx    = 0
    for pixel in pixels:
        # extract RGB
        r, g, b = pixel[:3]

        if bit_idx < len(bits):
            r = (r & ~1) | bits[bit_idx]; bit_idx += 1
        if bit_idx < len(bits):
            g = (g & ~1) | bits[bit_idx]; bit_idx += 1
        if bit_idx < len(bits):
            b = (b & ~1) | bits[bit_idx]; bit_idx += 1

        # preserve alpha if present
        if len(pixel) == 4:
            new_pixels.append((r, g, b, pixel[3]))
        else:
            new_pixels.append((r, g, b))

    out = Image.new(img.mode, img.size)
    out.putdata(new_pixels)
    out.save(png_out, "PNG")

def extract_message(png_in: str, txt_out: str, password: str):
    img    = Image.open(png_in)
    pixels = list(img.getdata())

    # read length prefix (32 bits)
    bits = []
    for pixel in pixels:
        r, g, b = pixel[:3]
        bits.append(r & 1)
        if len(bits) >= 32: break
        bits.append(g & 1)
        if len(bits) >= 32: break
        bits.append(b & 1)
        if len(bits) >= 32: break

    total_len = struct.unpack(">I", bits_to_bytes(bits[:32]))[0]

    # read full payload bits
    bits = []
    need = (4 + total_len) * 8
    for pixel in pixels:
        r, g, b = pixel[:3]
        bits.append(r & 1)
        if len(bits) >= need: break
        bits.append(g & 1)
        if len(bits) >= need: break
        bits.append(b & 1)
        if len(bits) >= need: break

    data = bits_to_bytes(bits[32:32 + total_len * 8])

    # parse payload
    if not data.startswith(MARKER):
        raise ValueError("Marca não encontrada.")

    pos    = len(MARKER)
    salt   = data[pos:pos + SALT_SIZE]; pos += SALT_SIZE
    nonce  = data[pos:pos + NONCE_SIZE]; pos += NONCE_SIZE
    ct_tag = data[pos:-HMAC_SIZE]
    tag    = data[-HMAC_SIZE:]

    aes_key, hmac_key = derive_keys(password, salt)

    # verify HMAC
    h = HMAC.new(hmac_key, digestmod=SHA256)
    h.update(data[:-HMAC_SIZE])
    h.verify(tag)

    # decrypt
    ct, gcm_tag = ct_tag[:-16], ct_tag[-16:]
    cipher      = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
    plaintext   = cipher.decrypt_and_verify(ct, gcm_tag)

    with open(txt_out, "wb") as f:
        f.write(plaintext)

def detect_message(png_in: str) -> bool:
    img    = Image.open(png_in)
    pixels = list(img.getdata())

    # read bits up to marker offset
    needed = 32 + len(MARKER) * 8
    bits   = []

    for pixel in pixels:
        r, g, b = pixel[:3]
        bits.append(r & 1)
        if len(bits) >= needed: break
        bits.append(g & 1)
        if len(bits) >= needed: break
        bits.append(b & 1)
        if len(bits) >= needed: break

    raw = bits_to_bytes(bits[32:needed])
    return raw.startswith(MARKER)

class Splash(tk.Toplevel):
    def __init__(self, master, img_file, size=250, delay=2000):
        super().__init__(master)
        self.overrideredirect(True)
        self.size, self.delay = size, delay
        self._set_icon()
        self._load_image(img_file)
        self._center()
        self.after(self.delay, self._close)

    def _set_icon(self):
        ico = resource_path("BitShadowIcon2.ico")
        try:
            self.iconbitmap(ico)
        except:
            pass
        pil_img      = Image.open(ico)
        self._icon   = ImageTk.PhotoImage(pil_img)
        self.iconphoto(False, self._icon)

    def _load_image(self, img_file):
        img = Image.open(resource_path(img_file))
        img = img.resize((self.size, self.size), Image.Resampling.LANCZOS)
        self.photo = ImageTk.PhotoImage(img)
        tk.Label(self, image=self.photo).pack()

    def _center(self):
        sw, sh = self.winfo_screenwidth(), self.winfo_screenheight()
        x = (sw - self.size)//2
        y = (sh - self.size)//2
        self.geometry(f"{self.size}x{self.size}+{x}+{y}")

    def _close(self):
        self.destroy()
        self.master.deiconify()

class BitShadow(tk.Tk):
    def __init__(self):
        super().__init__()
        self.withdraw()
        self.title("BitShadow")
        self._set_icon()
        self._center(600, 440)
        self._build_ui()
        Splash(self, "BitShadowIcon.png", size=250, delay=2000)

    def _set_icon(self):
        ico = resource_path("BitShadowIcon2.ico")
        try:
            self.iconbitmap(ico)
        except:
            pass
        pil_img      = Image.open(ico)
        self._icon   = ImageTk.PhotoImage(pil_img)
        self.iconphoto(False, self._icon)

    def _center(self, w, h):
        sw, sh = self.winfo_screenwidth(), self.winfo_screenheight()
        x = (sw - w)//2
        y = (sh - h)//2
        self.geometry(f"{w}x{h}+{x}+{y}")

    def _build_ui(self):
        nb = ttk.Notebook(self)
        nb.pack(fill="both", expand=True, padx=10, pady=10)

        # — Encriptar tab —
        tab1 = ttk.Frame(nb)
        nb.add(tab1, text="Encriptar")
        self.png_in  = tk.StringVar()
        self.txt_in  = tk.StringVar()
        self.png_out = tk.StringVar()
        self.pw_e    = tk.StringVar()
        self.show_e  = tk.BooleanVar(value=False)

        for label, var, cmd in [
            ("PNG de entrada:", self.png_in,  lambda: self._select_file(self.png_in, "PNG")),
            ("TXT a embutir:",  self.txt_in,  lambda: self._select_file(self.txt_in, "TXT")),
            ("Salvar PNG em:",  self.png_out, lambda: self._save_file(self.png_out, "png")),
        ]:
            ttk.Label(tab1, text=label).pack(anchor="w", pady=(5,0))
            frame = ttk.Frame(tab1); frame.pack(fill="x")
            ttk.Entry(frame, textvariable=var, width=50).pack(side="left", expand=True)
            ttk.Button(frame, text="Selecionar", command=cmd).pack(side="left", padx=5)

        ttk.Label(tab1, text="Senha:").pack(anchor="w", pady=(10,0))
        frame_pw = ttk.Frame(tab1); frame_pw.pack(fill="x")
        ent_pw = ttk.Entry(frame_pw, textvariable=self.pw_e, show="*")
        ent_pw.pack(side="left", fill="x", expand=True)
        ttk.Button(
            frame_pw,
            text="Mostrar",
            command=lambda: self._toggle_pw(ent_pw, self.show_e)
        ).pack(side="left", padx=5)

        self.btn_e = ttk.Button(tab1, text="Encriptar", command=self._start_encrypt)
        self.btn_e.pack(pady=10)
        self.pb_e  = ttk.Progressbar(tab1, mode="indeterminate")
        self.pb_e.pack(fill="x")

        # — Desencriptar tab —
        tab2 = ttk.Frame(nb)
        nb.add(tab2, text="Desencriptar")
        self.png_in2 = tk.StringVar()
        self.pw_d    = tk.StringVar()
        self.show_d  = tk.BooleanVar(value=False)

        ttk.Label(tab2, text="PNG com mensagem:").pack(anchor="w", pady=(5,0))
        frame2 = ttk.Frame(tab2); frame2.pack(fill="x")
        ttk.Entry(frame2, textvariable=self.png_in2, width=50).pack(side="left", expand=True)
        ttk.Button(frame2, text="Selecionar", command=self._on_select_png2).pack(side="left", padx=5)

        ttk.Label(tab2, text="Senha:").pack(anchor="w", pady=(10,0))
        frame_pw2 = ttk.Frame(tab2); frame_pw2.pack(fill="x")
        ent_pw2 = ttk.Entry(frame_pw2, textvariable=self.pw_d, show="*")
        ent_pw2.pack(side="left", fill="x", expand=True)
        ttk.Button(
            frame_pw2,
            text="Mostrar",
            command=lambda: self._toggle_pw(ent_pw2, self.show_d)
        ).pack(side="left", padx=5)

        # Campo para salvar texto revelado
        self.txt_out = tk.StringVar()
        ttk.Label(tab2, text="Salvar texto em:").pack(anchor="w", pady=(5,0))
        frame_txt = ttk.Frame(tab2); frame_txt.pack(fill="x")
        ttk.Entry(frame_txt, textvariable=self.txt_out, width=50).pack(side="left", expand=True)
        ttk.Button(
            frame_txt,
            text="Selecionar",
            command=lambda: self._save_file(self.txt_out, "txt")
        ).pack(side="left", padx=5)

        self.btn_d = ttk.Button(tab2, text="Desencriptar", command=self._start_decrypt)
        self.btn_d.pack(pady=10)
        self.pb_d  = ttk.Progressbar(tab2, mode="indeterminate")
        self.pb_d.pack(fill="x")

    def _select_file(self, var, ftype):
        p = filedialog.askopenfilename(filetypes=[(ftype, f"*.{ftype.lower()}")])
        if p: var.set(p)

    def _save_file(self, var, ext):
        p = filedialog.asksaveasfilename(defaultextension=f".{ext}", filetypes=[(ext.upper(), f"*.{ext}")])
        if p: var.set(p)

    def _toggle_pw(self, entry, flag):
        flag.set(not flag.get())
        entry.config(show="" if flag.get() else "*")

    def _start_encrypt(self):
        self.btn_e.config(state="disabled")
        self.pb_e.start(10)
        threading.Thread(target=self._do_encrypt, daemon=True).start()

    def _do_encrypt(self):
        try:
            embed_message(
                self.png_in.get(),
                self.png_out.get(),
                self.txt_in.get(),
                self.pw_e.get()
            )
            ok, msg = True, "Encriptado com sucesso!"
        except Exception as e:
            ok, msg = False, str(e)
        self.after(0, lambda: self._finish_encrypt(ok, msg))

    def _finish_encrypt(self, ok, msg):
        self.pb_e.stop()
        self.btn_e.config(state="normal")
        (messagebox.showinfo if ok else messagebox.showerror)("Status", msg)

    def _on_select_png2(self):
        p = filedialog.askopenfilename(filetypes=[("PNG", "*.png")])
        if not p: return
        self.png_in2.set(p)
        try:
            found = detect_message(p)
            messagebox.showinfo("Detectar", "Mensagem oculta encontrada." if found else "Nenhuma mensagem oculta.")
        except:
            messagebox.showwarning("Erro", "Falha ao analisar a imagem.")

    def _start_decrypt(self):
        self.btn_d.config(state="disabled")
        self.pb_d.start(10)
        threading.Thread(target=self._do_decrypt, daemon=True).start()

    def _do_decrypt(self):
        out_txt = self.txt_out.get() or os.path.join(os.getcwd(), "TextoReveladoBS.txt")
        try:
            extract_message(
                self.png_in2.get(),
                out_txt,
                self.pw_d.get()
            )
            ok, msg = True, f"Texto revelado salvo em:\n{out_txt}"
        except Exception as e:
            ok, msg = False, str(e)
        self.after(0, lambda: self._finish_decrypt(ok, msg))

    def _finish_decrypt(self, ok, msg):
        self.pb_d.stop()
        self.btn_d.config(state="normal")
        (messagebox.showinfo if ok else messagebox.showerror)("Status", msg)

if __name__ == "__main__":
    app = BitShadow()
    app.mainloop()
