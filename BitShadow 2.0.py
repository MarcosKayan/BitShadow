import os
import sys
import struct
import threading
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

from PIL import Image, ImageTk

from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA256
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Random import get_random_bytes

from argon2.low_level import Type, hash_secret_raw

# ==== KDF PARAMETERS ====
# PBKDF2
PBKDF2_ITERS        = 1_000_000
SALT_SIZE_PBKDF2    = 16

# Argon2id
TIME_COST           = 6
MEMORY_COST         = 524_288    # in KiB (512 MiB)
PARALLELISM         = 4
SALT_SIZE_ARGON2    = 32
HASH_LEN            = 64

# Other crypto
NONCE_SIZE          = 12
HMAC_SIZE           = 32
MARKER              = b'BITSHDW1'   # 8-byte signature


def resource_path(rel_path: str) -> str:
    """Get absolute path to resource, works with PyInstaller."""
    try:
        base = sys._MEIPASS
    except AttributeError:
        base = os.path.abspath(".")
    return os.path.join(base, rel_path)


def derive_keys(password: str, salt: bytes) -> tuple[bytes, bytes]:
    """
    Derive AES and HMAC keys:
      - PBKDF2 if salt length == SALT_SIZE_PBKDF2
      - Argon2id if salt length == SALT_SIZE_ARGON2
    """
    pwd = password.encode("utf-8")

    if len(salt) == SALT_SIZE_PBKDF2:
        km = PBKDF2(pwd, salt, dkLen=64, count=PBKDF2_ITERS, hmac_hash_module=SHA256)
    elif len(salt) == SALT_SIZE_ARGON2:
        km = hash_secret_raw(
            secret=pwd,
            salt=salt,
            time_cost=TIME_COST,
            memory_cost=MEMORY_COST,
            parallelism=PARALLELISM,
            hash_len=HASH_LEN,
            type=Type.ID
        )
    else:
        raise ValueError("Unsupported salt length for key derivation")

    return km[:32], km[32:64]  # AES key, HMAC key


def bytes_to_bits(data: bytes) -> list[int]:
    bits: list[int] = []
    for b in data:
        for i in range(8):
            bits.append((b >> (7 - i)) & 1)
    return bits


def bits_to_bytes(bits: list[int]) -> bytes:
    b = bytearray(len(bits) // 8)
    for i, bit in enumerate(bits):
        b[i // 8] |= bit << (7 - (i % 8))
    return bytes(b)


def embed_message(png_in: str, png_out: str, txt_in: str,
                  password: str, kdf_method: str):
    # load plaintext
    with open(txt_in, "rb") as f:
        plaintext = f.read()

    # choose salt
    if kdf_method == "PBKDF2":
        salt = get_random_bytes(SALT_SIZE_PBKDF2)
    elif kdf_method == "Argon2id":
        salt = get_random_bytes(SALT_SIZE_ARGON2)
    else:
        raise ValueError("Método de derivação desconhecido")

    # derive keys
    aes_key, hmac_key = derive_keys(password, salt)

    # encrypt under AES-GCM
    nonce = get_random_bytes(NONCE_SIZE)
    cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
    ct, gcm_tag = cipher.encrypt_and_digest(plaintext)

    # construct payload: marker | salt | nonce | ciphertext | gcm_tag
    payload = MARKER + salt + nonce + ct + gcm_tag

    # append HMAC
    h = HMAC.new(hmac_key, digestmod=SHA256)
    h.update(payload)
    full = payload + h.digest()

    # prefix with 4-byte length
    data = struct.pack(">I", len(full)) + full
    bits = bytes_to_bits(data)

    # open and check capacity
    img = Image.open(png_in)
    w, h = img.size
    pixels = list(img.getdata())
    capacity = w * h * 3
    if len(bits) > capacity:
        raise ValueError("Imagem não comporta todos os dados.")

    # embed bits into LSB of RGB
    new_pixels = []
    bit_idx = 0
    for px in pixels:
        r, g, b = px[:3]
        if bit_idx < len(bits):
            r = (r & ~1) | bits[bit_idx]; bit_idx += 1
        if bit_idx < len(bits):
            g = (g & ~1) | bits[bit_idx]; bit_idx += 1
        if bit_idx < len(bits):
            b = (b & ~1) | bits[bit_idx]; bit_idx += 1

        new_pixels.append((r, g, b) + px[3:] if len(px) == 4 else (r, g, b))

    out = Image.new(img.mode, img.size)
    out.putdata(new_pixels)
    out.save(png_out, "PNG")


def extract_message(png_in: str, txt_out: str, password: str):
    img = Image.open(png_in)
    pixels = list(img.getdata())

    # read 32 bits of length prefix
    bits = []
    for px in pixels:
        for ch in px[:3]:
            bits.append(ch & 1)
            if len(bits) >= 32:
                break
        if len(bits) >= 32:
            break

    total_len = struct.unpack(">I", bits_to_bytes(bits[:32]))[0]

    # read the full payload+HMAC bits
    need = (4 + total_len) * 8
    bits = []
    for px in pixels:
        for ch in px[:3]:
            bits.append(ch & 1)
            if len(bits) >= need:
                break
        if len(bits) >= need:
            break

    full = bits_to_bytes(bits[32:32 + total_len * 8])

    if not full.startswith(MARKER):
        raise ValueError("Marca não encontrada.")

    # strip marker and split
    body = full[len(MARKER):]
    hmac_tag = body[-HMAC_SIZE:]
    payload = body[:-HMAC_SIZE]

    # try PBKDF2 first
    salt16 = payload[:SALT_SIZE_PBKDF2]
    try:
        aes_key, hmac_key = derive_keys(password, salt16)
        h = HMAC.new(hmac_key, digestmod=SHA256)
        h.update(MARKER + salt16 + payload[SALT_SIZE_PBKDF2:])
        h.verify(hmac_tag)
        salt = salt16
        offset = SALT_SIZE_PBKDF2
    except Exception:
        # fallback to Argon2id
        salt32 = payload[:SALT_SIZE_ARGON2]
        aes_key, hmac_key = derive_keys(password, salt32)
        h = HMAC.new(hmac_key, digestmod=SHA256)
        h.update(MARKER + salt32 + payload[SALT_SIZE_ARGON2:])
        h.verify(hmac_tag)
        salt = salt32
        offset = SALT_SIZE_ARGON2

    # extract nonce, ciphertext and GCM tag
    nonce = payload[offset:offset + NONCE_SIZE]
    rest  = payload[offset + NONCE_SIZE:]
    ct, gcm_tag = rest[:-16], rest[-16:]

    # decrypt
    cipher = AES.new(aes_key, AES.MODE_GCM, nonce=nonce)
    plaintext = cipher.decrypt_and_verify(ct, gcm_tag)

    with open(txt_out, "wb") as f:
        f.write(plaintext)


def detect_message(png_in: str) -> bool:
    img = Image.open(png_in)
    pixels = list(img.getdata())

    needed = 32 + len(MARKER) * 8
    bits = []
    for px in pixels:
        for ch in px[:3]:
            bits.append(ch & 1)
            if len(bits) >= needed:
                break
        if len(bits) >= needed:
            break

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
        img = Image.open(ico)
        self._icon = ImageTk.PhotoImage(img)
        self.iconphoto(False, self._icon)

    def _load_image(self, img_file):
        img = Image.open(resource_path(img_file))
        img = img.resize((self.size, self.size), Image.Resampling.LANCZOS)
        self.photo = ImageTk.PhotoImage(img)
        tk.Label(self, image=self.photo).pack()

    def _center(self):
        sw, sh = self.winfo_screenwidth(), self.winfo_screenheight()
        x = (sw - self.size) // 2
        y = (sh - self.size) // 2
        self.geometry(f"{self.size}x{self.size}+{x}+{y}")

    def _close(self):
        self.destroy()
        self.master.deiconify()


class BitShadowApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.withdraw()
        self.title("BitShadow 2.0")
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
        img = Image.open(ico)
        self._icon = ImageTk.PhotoImage(img)
        self.iconphoto(False, self._icon)

    def _center(self, w, h):
        sw, sh = self.winfo_screenwidth(), self.winfo_screenheight()
        x = (sw - w) // 2
        y = (sh - h) // 2
        self.geometry(f"{w}x{h}+{x}+{y}")

    def _build_ui(self):
        nb = ttk.Notebook(self)
        nb.pack(fill="both", expand=True, padx=10, pady=10)

        # ---- Encrypt Tab ----
        tab_e = ttk.Frame(nb)
        nb.add(tab_e, text="Encriptar")

        self.png_in   = tk.StringVar()
        self.txt_in   = tk.StringVar()
        self.png_out  = tk.StringVar()
        self.pw_e      = tk.StringVar()
        self.show_e = tk.BooleanVar(value=False)
        self.kdf_method = tk.StringVar(value="PBKDF2")

        # File selectors
        for lbl, var, cmd in [
            ("PNG de entrada:", self.png_in, lambda: self._select_file(self.png_in, "PNG")),
            ("TXT a embutir:", self.txt_in, lambda: self._select_file(self.txt_in, "TXT")),
            ("Salvar PNG em:", self.png_out, lambda: self._save_file(self.png_out, "png")),
        ]:
            ttk.Label(tab_e, text=lbl).pack(anchor="w", pady=(5, 0))
            frm = ttk.Frame(tab_e); frm.pack(fill="x")
            ttk.Entry(frm, textvariable=var, width=50).pack(side="left", expand=True)
            ttk.Button(frm, text="Selecionar", command=cmd).pack(side="left", padx=5)

        # Password
        ttk.Label(tab_e, text="Senha:").pack(anchor="w", pady=(10, 0))
        frm_pw = ttk.Frame(tab_e); frm_pw.pack(fill="x")
        ent_pw = ttk.Entry(frm_pw, textvariable=self.pw_e, show="*")
        ent_pw.pack(side="left", fill="x", expand=True)
        ttk.Button(frm_pw, text="Mostrar",
                   command=lambda: self._toggle_pw(ent_pw, self.show_e)).pack(side="left", padx=5)

        # KDF selection
        ttk.Label(tab_e, text="Método de derivação de chave:").pack(anchor="w", pady=(10, 0))
        frm_kdf = ttk.Frame(tab_e); frm_kdf.pack(fill="x")
        ttk.Radiobutton(frm_kdf, text="PBKDF2 (iter=1e6, salt=16B)",
                        variable=self.kdf_method, value="PBKDF2").pack(side="left", padx=5)
        ttk.Radiobutton(frm_kdf, text="Argon2id (t=6, m=512MiB, p=4, len=64B)",
                        variable=self.kdf_method, value="Argon2id").pack(side="left", padx=5)

        # Encrypt button & progress
        self.btn_e = ttk.Button(tab_e, text="Encriptar", command=self._start_encrypt)
        self.btn_e.pack(pady=15)
        self.pb_e = ttk.Progressbar(tab_e, mode="indeterminate")
        self.pb_e.pack(fill="x")

        # ---- Decrypt Tab ----
        tab_d = ttk.Frame(nb)
        nb.add(tab_d, text="Desencriptar")

        self.png_in2 = tk.StringVar()
        self.pw_d      = tk.StringVar()
        self.show_d = tk.BooleanVar(value=False)
        self.txt_out   = tk.StringVar()

        ttk.Label(tab_d, text="PNG com mensagem:").pack(anchor="w", pady=(5, 0))
        frm2 = ttk.Frame(tab_d); frm2.pack(fill="x")
        ttk.Entry(frm2, textvariable=self.png_in2, width=50).pack(side="left", expand=True)
        ttk.Button(frm2, text="Selecionar", command=self._on_select_png2).pack(side="left", padx=5)

        ttk.Label(tab_d, text="Senha:").pack(anchor="w", pady=(10, 0))
        frm_pw2 = ttk.Frame(tab_d); frm_pw2.pack(fill="x")
        ent_pw2 = ttk.Entry(frm_pw2, textvariable=self.pw_d, show="*")
        ent_pw2.pack(side="left", fill="x", expand=True)
        ttk.Button(frm_pw2, text="Mostrar",
                   command=lambda: self._toggle_pw(ent_pw2, self.show_d)).pack(side="left", padx=5)

        ttk.Label(tab_d, text="Salvar texto em:").pack(anchor="w", pady=(10, 0))
        frm_txt = ttk.Frame(tab_d); frm_txt.pack(fill="x")
        ttk.Entry(frm_txt, textvariable=self.txt_out, width=50).pack(side="left", expand=True)
        ttk.Button(frm_txt, text="Selecionar",
                   command=lambda: self._save_file(self.txt_out, "txt")).pack(side="left", padx=5)

        self.btn_d = ttk.Button(tab_d, text="Desencriptar", command=self._start_decrypt)
        self.btn_d.pack(pady=15)
        self.pb_d = ttk.Progressbar(tab_d, mode="indeterminate")
        self.pb_d.pack(fill="x")

    def _select_file(self, var, ftype):
        p = filedialog.askopenfilename(filetypes=[(ftype, f"*.{ftype.lower()}")])
        if p: var.set(p)

    def _save_file(self, var, ext):
        p = filedialog.asksaveasfilename(defaultextension=f".{ext}",
                                         filetypes=[(ext.upper(), f"*.{ext}")])
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
                self.pw_e.get(),
                self.kdf_method.get()
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
            messagebox.showinfo("Detectar",
                                "Mensagem oculta encontrada." if found else "Nenhuma mensagem oculta.")
        except:
            messagebox.showwarning("Erro", "Falha ao analisar a imagem.")

    def _start_decrypt(self):
        self.btn_d.config(state="disabled")
        self.pb_d.start(10)
        threading.Thread(target=self._do_decrypt, daemon=True).start()

    def _do_decrypt(self):
        out_txt = self.txt_out.get() or os.path.join(os.getcwd(), "TextoReveladoBS2.txt")
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
    app = BitShadowApp()
    app.mainloop()
