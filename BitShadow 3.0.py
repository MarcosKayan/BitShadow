#!/usr/bin/env python3
import os
import sys
import struct
import hmac
import hashlib
import random
from concurrent.futures import ProcessPoolExecutor
from multiprocessing import Pipe
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
try:
    from tkinterdnd2 import TkinterDnD, DND_FILES
except ImportError:
    DND_FILES = None
    TkinterDnD = tk.Tk
from PIL import Image, ImageTk, UnidentifiedImageError
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from argon2.low_level import Type, hash_secret_raw

# Constants
NONCE_SIZE = 12
GCM_TAG_SIZE = 16
ARGON_HASH_LEN = 32
HMAC_SIZE = 32
VALID_SALT_SIZES = (16, 32, 64)
MIN_TIME_COST, MAX_TIME_COST = 2, 15
VALID_MEM_MB = {64, 128, 256, 512, 1024, 2048, 4096}
MIN_PARALLELISM, MAX_PARALLELISM = 1, 8

def resource_path(rel_path: str) -> str:
    """Resolve path para recursos empacotados (PyInstaller)."""
    try:
        base = sys._MEIPASS
    except AttributeError:
        base = os.path.abspath(".")
    return os.path.join(base, rel_path)

def derive_key(password: str, salt: bytes,
               time_cost: int, memory_kib: int, parallelism: int) -> bytes:
    """Argon2id key derivation (32 bytes)."""
    return hash_secret_raw(
        password.encode("utf-8"), salt,
        time_cost, memory_kib, parallelism,
        ARGON_HASH_LEN, Type.ID
    )

def bits_to_bytes(bits: list[int]) -> bytes:
    """Pack list of bits (0/1) into bytes."""
    out = bytearray()
    for i in range(0, len(bits), 8):
        byte = 0
        for b in bits[i:i+8]:
            byte = (byte << 1) | b
        out.append(byte)
    return bytes(out)

def bytes_to_bits(data: bytes) -> list[int]:
    """Unpack bytes into a list of bits (0/1)."""
    bits: list[int] = []
    for b in data:
        for i in range(8):
            bits.append((b >> (7 - i)) & 1)
    return bits

def validate_parameters(salt_len, time_cost, mem_mb, parallelism):
    if salt_len not in VALID_SALT_SIZES:
        raise ValueError(f"Salt_len deve ser um de {VALID_SALT_SIZES}")
    if not (MIN_TIME_COST <= time_cost <= MAX_TIME_COST):
        raise ValueError(f"Time_cost deve estar entre {MIN_TIME_COST} e {MAX_TIME_COST}")
    if mem_mb not in VALID_MEM_MB:
        raise ValueError(f"Memory_cost deve ser um de {sorted(VALID_MEM_MB)}")
    if not (MIN_PARALLELISM <= parallelism <= MAX_PARALLELISM):
        raise ValueError(f"Parallelism deve estar entre {MIN_PARALLELISM} e {MAX_PARALLELISM}")

def embed_message(png_in: str, png_out: str, txt_in: str, password: str,
                  salt_len: int, time_cost: int, mem_mb: int, parallelism: int,
                  progress_conn=None) -> None:
    """Embed and encrypt the text into the PNG via dispersed LSB + AES-GCM + HMAC."""
    # Validate inputs
    validate_parameters(salt_len, time_cost, mem_mb, parallelism)
    if not os.path.isfile(png_in):
        raise FileNotFoundError(f"PNG de entrada não encontrado: {png_in}")
    if not os.access(png_in, os.R_OK):
        raise PermissionError(f"Sem permissão para ler: {png_in}")
    if not os.path.isfile(txt_in):
        raise FileNotFoundError(f"TXT de entrada não encontrado: {txt_in}")
    if not os.access(txt_in, os.R_OK):
        raise PermissionError(f"Sem permissão para ler: {txt_in}")
    out_dir = os.path.dirname(png_out) or "."
    if not os.path.isdir(out_dir) or not os.access(out_dir, os.W_OK):
        raise PermissionError(f"Sem permissão para salvar em: {out_dir}")

    try:
        payload = open(txt_in, "rb").read()
    except Exception as e:
        raise IOError(f"Falha ao ler TXT: {e}")

    salt = get_random_bytes(salt_len)
    key = derive_key(password, salt, time_cost, mem_mb * 1024, parallelism)

    try:
        nonce = get_random_bytes(NONCE_SIZE)
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        ct, tag = cipher.encrypt_and_digest(payload)
    except Exception as e:
        raise RuntimeError(f"Erro na criptografia AES-GCM: {e}")

    dyn = nonce + ct + tag
    dyn_len = len(dyn)

    seed = get_random_bytes(16)
    seed_int = int.from_bytes(seed, "big")
    hdr_wo_h = (
        seed
        + struct.pack(">B", salt_len)
        + dyn_len.to_bytes(4, "big")
        + salt
    )
    signature = hmac.new(key, hdr_wo_h, hashlib.sha256).digest()
    full = hdr_wo_h + signature + dyn
    bits = bytes_to_bits(full)

    try:
        img = Image.open(png_in)
        raw = bytearray(img.tobytes())
    except UnidentifiedImageError:
        raise ValueError("Arquivo de entrada não é um PNG válido")
    except Exception as e:
        raise RuntimeError(f"Erro ao abrir imagem: {e}")

    capacity = len(raw)
    if len(bits) > capacity:
        raise ValueError("Imagem sem capacidade suficiente")

    # Embed header
    for i in range(16 * 8):
        raw[i] = (raw[i] & ~1) | bits[i]
        if progress_conn and i % 1000 == 0:
            progress_conn.send(("tick",))

    # Embed rest in pseudo-aleatório
    rnd = random.Random(seed_int)
    tail_positions = list(range(16 * 8, capacity))
    rnd.shuffle(tail_positions)
    for idx, bit in enumerate(bits[16 * 8:], 0):
        pos = tail_positions[idx]
        raw[pos] = (raw[pos] & ~1) | bit
        if progress_conn and ((16 * 8 + idx) % 1000) == 0:
            progress_conn.send(("tick",))

    try:
        out = Image.frombytes(img.mode, img.size, bytes(raw))
        out.save(png_out, "PNG")
    except Exception as e:
        raise IOError(f"Falha ao salvar PNG de saída: {e}")

    if progress_conn:
        progress_conn.send(("done",))


def extract_message(png_in: str, txt_out: str, password: str,
                    time_cost: int, mem_mb: int, parallelism: int,
                    progress_conn=None) -> None:
    """Decrypt and extract the embedded text from the PNG."""
    
    if not os.path.isfile(png_in):
        raise FileNotFoundError(f"PNG de entrada não encontrado: {png_in}")
    if not os.access(png_in, os.R_OK):
        raise PermissionError(f"Sem permissão para ler: {png_in}")
    out_dir = os.path.dirname(txt_out) or "."
    if not os.path.isdir(out_dir) or not os.access(out_dir, os.W_OK):
        raise PermissionError(f"Sem permissão para salvar em: {out_dir}")

    try:
        img = Image.open(png_in)
        raw = bytearray(img.tobytes())
    except UnidentifiedImageError:
        raise ValueError("Arquivo de entrada não é um PNG válido")
    except Exception as e:
        raise RuntimeError(f"Erro ao abrir imagem: {e}")

    capacity = len(raw)
    seed_bits = [raw[i] & 1 for i in range(16 * 8)]
    seed = bits_to_bytes(seed_bits)
    seed_int = int.from_bytes(seed, "big")
    rnd = random.Random(seed_int)
    tail = list(range(16 * 8, capacity))
    rnd.shuffle(tail)

    salt_len = bits_to_bytes([raw[p] & 1 for p in tail[0:8]])[0]
    if salt_len not in VALID_SALT_SIZES:
        raise ValueError(f"Salt extraído inválido ({salt_len}); deve ser um de {VALID_SALT_SIZES}")

    validate_parameters(salt_len, time_cost, mem_mb, parallelism)
    hdr_bits = tail[8:8 + (4 + salt_len) * 8]
    hdr_bytes = bits_to_bytes([raw[p] & 1 for p in hdr_bits])

    dyn_len = int.from_bytes(hdr_bytes[0:4], "big")
    salt = hdr_bytes[4:4 + salt_len]

    sig_start = 8 + (4 + salt_len) * 8
    sig_bits = tail[sig_start:sig_start + HMAC_SIZE * 8]
    recv_mac = bits_to_bytes([raw[p] & 1 for p in sig_bits])

    hdr_wo_h = (
        seed
        + struct.pack(">B", salt_len)
        + dyn_len.to_bytes(4, "big")
        + salt
    )
    key = derive_key(password, salt, time_cost, mem_mb * 1024, parallelism)
    exp_mac = hmac.new(key, hdr_wo_h, hashlib.sha256).digest()
    if not hmac.compare_digest(exp_mac, recv_mac):
        raise ValueError("Senha incorreta ou dados corrompidos")

    if progress_conn:
        progress_conn.send(("start", (dyn_len * 8) // 1000))

    body_start = sig_start + HMAC_SIZE * 8
    body_bits = tail[body_start:body_start + dyn_len * 8]
    dyn = bits_to_bytes([raw[p] & 1 for p in body_bits])

    nonce = dyn[:NONCE_SIZE]
    tag = dyn[-GCM_TAG_SIZE:]
    ct = dyn[NONCE_SIZE:-GCM_TAG_SIZE]

    try:
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        plaintext = cipher.decrypt_and_verify(ct, tag)
    except ValueError:
        raise ValueError("Dados corrompidos ou senha inválida")
    except Exception as e:
        raise RuntimeError(f"Erro na descriptografia AES-GCM: {e}")

    try:
        with open(txt_out, "wb") as f:
            f.write(plaintext)
    except Exception as e:
        raise IOError(f"Falha ao salvar TXT de saída: {e}")

    if progress_conn:
        progress_conn.send(("done",))


def detect_message(png_in: str, password: str,
                   time_cost: int, mem_mb: int, parallelism: int) -> bool:
    """Check if there is a hidden message inside the PNG."""
    try:
        img = Image.open(png_in)
        raw = bytearray(img.tobytes())
        capacity = len(raw)

        seed_bits = [raw[i] & 1 for i in range(16 * 8)]
        seed = bits_to_bytes(seed_bits)
        seed_int = int.from_bytes(seed, "big")
        rnd = random.Random(seed_int)
        tail = list(range(16 * 8, capacity))
        rnd.shuffle(tail)

        salt_len = bits_to_bytes([raw[p] & 1 for p in tail[0:8]])[0]
        hdr_bits = tail[8:8 + (4 + salt_len) * 8]
        hdr_bytes = bits_to_bytes([raw[p] & 1 for p in hdr_bits])

        dyn_len = int.from_bytes(hdr_bytes[0:4], "big")
        salt = hdr_bytes[4:4 + salt_len]

        sig_start = 8 + (4 + salt_len) * 8
        sig_bits = tail[sig_start:sig_start + HMAC_SIZE * 8]
        recv_mac = bits_to_bytes([raw[p] & 1 for p in sig_bits])

        hdr_wo_h = (
            seed
            + struct.pack(">B", salt_len)
            + dyn_len.to_bytes(4, "big")
            + salt
        )
        key = derive_key(password, salt, time_cost, mem_mb * 1024, parallelism)
        expected = hmac.new(key, hdr_wo_h, hashlib.sha256).digest()

        return hmac.compare_digest(expected, recv_mac)
    except Exception:
        return False


class Splash(tk.Toplevel):
    """Splash screen window."""
    def __init__(self, master, img_file, size=250, delay=1500):
        super().__init__(master)
        self.overrideredirect(True)
        try:
            self.iconbitmap(resource_path("BitShadowIcon2.ico"))
        except Exception:
            pass
        img = Image.open(resource_path(img_file))
        img = img.resize((size, size), Image.Resampling.LANCZOS)
        self.photo = ImageTk.PhotoImage(img)
        tk.Label(self, image=self.photo).pack()
        sw, sh = self.winfo_screenwidth(), self.winfo_screenheight()
        x, y = (sw - size) // 2, (sh - size) // 2
        self.geometry(f"{size}x{size}+{x}+{y}")
        self.after(delay, self.close)

    def close(self):
        self.destroy()
        self.master.deiconify()


class BitShadowApp(TkinterDnD.Tk):
    def __init__(self):
        super().__init__()
        self.withdraw()
        self.title("BitShadow 3.0")
        ico = resource_path("BitShadowIcon2.ico")
        try:
            self.iconbitmap(ico)
            self.iconphoto(False, ImageTk.PhotoImage(Image.open(ico)))
        except Exception:
            pass
        sw, sh = self.winfo_screenwidth(), self.winfo_screenheight()
        self.geometry(f"620x540+{(sw-620)//2}+{(sh-540)//2}")
        Splash(self, "BitShadowIcon.png", size=250, delay=1500)
        self.executor = ProcessPoolExecutor(max_workers=2)
        self._build_ui()

    def _build_ui(self):
        nb = ttk.Notebook(self)
        nb.pack(fill="both", expand=True, padx=10, pady=10)

        # Vars para criptografia
        self.arg_salt = tk.IntVar(value=16)
        self.arg_time = tk.IntVar(value=2)
        self.arg_mem = tk.StringVar(value="64")
        self.arg_par = tk.IntVar(value=1)

        # Vars para descriptografia
        self.arg_salt_d = tk.IntVar(value=16)
        self.arg_time_d = tk.IntVar(value=2)
        self.arg_mem_d = tk.StringVar(value="64")
        self.arg_par_d = tk.IntVar(value=1)

        # Aba 1: Encriptar
        f1 = ttk.Frame(nb)
        nb.add(f1, text="Encriptar")
        instr = (
            "Para o perfeito funcionamento das configurações do Argon2id, verifique as especificações de hardware do seu computador. "
        )
        ttk.Label(f1, text=instr, wraplength=580, foreground="gray30").pack(fill="x", pady=(6, 12))


        self._file_selector(f1, "PNG entrada:", "png_in", "PNG")
        self._file_selector(f1, "TXT a embutir:", "txt_in", "TXT")
        ttk.Label(f1, text="Salvar como (PNG):").pack(anchor="w", pady=(6, 0))
        o1 = ttk.Frame(f1); o1.pack(fill="x")
        self.png_out = tk.StringVar()
        ttk.Entry(o1, textvariable=self.png_out, width=50).pack(side="left", expand=True)
        ttk.Button(o1, text="Salvar em...", command=lambda: self._save_as(self.png_out, "PNG", ".png")).pack(side="left", padx=4)
        ttk.Label(f1, text="Senha:").pack(anchor="w", pady=(10, 0))
        pwf = ttk.Frame(f1); pwf.pack(fill="x")
        self.pw_e = tk.StringVar()
        self.e_pw_e = ttk.Entry(pwf, textvariable=self.pw_e, show="*")
        self.e_pw_e.pack(side="left", fill="x", expand=True)
        self.btn_show_e = ttk.Button(pwf, text="Mostrar", width=8, command=self._toggle_pw_e)
        self.btn_show_e.pack(side="left", padx=4)
        self._build_argon2_frame(f1, self.arg_salt, self.arg_time, self.arg_mem, self.arg_par)
        self.pr_lbl_e = ttk.Label(f1, text="0%")
        self.pr_lbl_e.pack(fill="x", pady=(12, 0))
        ttk.Button(f1, text="Encriptar", command=self._run_encrypt).pack(pady=10)

        # Aba 2: Desencriptar
        f2 = ttk.Frame(nb)
        nb.add(f2, text="Desencriptar")
        instr = (
            "Para autenticação prévia, insira a senha antes de selecionar a imagem PNG a descriptografar. "
            "As configurações do Argon2id deverão ser as mesmas com as quais o arquivo fora inicialmente encriptado. "
                     
        )
        ttk.Label(f2, text=instr, wraplength=580, foreground="gray30").pack(fill="x", pady=(6, 12))
        
        self._file_selector(f2, "PNG com mensagem:", "png_in_dec", "PNG", self._auto_detect)
        ttk.Label(f2, text="Salvar TXT como:").pack(anchor="w", pady=(6, 0))
        o2 = ttk.Frame(f2); o2.pack(fill="x")
        self.txt_out = tk.StringVar()
        ttk.Entry(o2, textvariable=self.txt_out, width=50).pack(side="left", expand=True)
        ttk.Button(o2, text="Salvar em...", command=lambda: self._save_as(self.txt_out, "TXT", ".txt")).pack(side="left", padx=4)
        ttk.Label(f2, text="Senha:").pack(anchor="w", pady=(10, 0))
        pwf2 = ttk.Frame(f2); pwf2.pack(fill="x")
        self.pw_d = tk.StringVar()
        self.e_pw_d = ttk.Entry(pwf2, textvariable=self.pw_d, show="*")
        self.e_pw_d.pack(side="left", fill="x", expand=True)
        self.btn_show_d = ttk.Button(pwf2, text="Mostrar", width=8, command=self._toggle_pw_d)
        self.btn_show_d.pack(side="left", padx=4)
        self._build_argon2_frame(f2, self.arg_salt_d, self.arg_time_d, self.arg_mem_d, self.arg_par_d)
        self.pr_lbl_d = ttk.Label(f2, text="0%")
        self.pr_lbl_d.pack(fill="x", pady=(12, 0))
        ttk.Button(f2, text="Extrair", command=self._run_decrypt).pack(pady=10)
        self.lbl_dt = ttk.Label(f2, text="")
        self.lbl_dt.pack()

    def _file_selector(self, parent, text, attr, ext, callback=None):
        ttk.Label(parent, text=text).pack(anchor="w", pady=(6, 0))
        frm = ttk.Frame(parent); frm.pack(fill="x")
        var = tk.StringVar(); setattr(self, attr, var)
        entry = ttk.Entry(frm, textvariable=var, width=50)
        entry.pack(side="left", expand=True)
        if DND_FILES:
            entry.drop_target_register(DND_FILES)
            entry.dnd_bind("<<Drop>>", lambda e, v=var: v.set(e.data.strip("{}")))
        ttk.Button(frm, text="Selecionar", command=lambda v=var: self._ask_open(v, ext)).pack(side="left", padx=4)
        if callback:
            var.trace_add("write", lambda *_: callback())

    def _ask_open(self, var, ext):
        p = filedialog.askopenfilename(filetypes=[(ext, f"*.{ext.lower()}")])
        if p:
            var.set(p)

    def _save_as(self, var, ext, defext):
        p = filedialog.asksaveasfilename(defaultextension=defext, filetypes=[(ext, f"*{defext}")])
        if p:
            var.set(p)

    def _build_argon2_frame(self, parent, salt_var, time_var, mem_var, par_var):
        frm = ttk.Labelframe(parent, text="Argon2id")
        frm.pack(fill="x", pady=(10, 0))
        salt_opts = ", ".join(str(s) for s in VALID_SALT_SIZES)
        ttk.Label(
            frm,
            text=f"Salt (bytes; opções: {salt_opts}):"
        ).grid(row=0, column=0, sticky="w", padx=5, pady=2)
        
        tk.Spinbox(frm, values=VALID_SALT_SIZES, textvariable=salt_var, width=5).grid(row=0, column=1)
        ttk.Label(
            frm,
            text=f"Time cost (iterações; {MIN_TIME_COST}–{MAX_TIME_COST}):"
        ).grid(row=1, column=0, sticky="w", padx=5, pady=2)

        tk.Spinbox(frm, from_=MIN_TIME_COST, to=MAX_TIME_COST, textvariable=time_var, width=5).grid(row=1, column=1)
        mem_opts = ", ".join(str(m) for m in sorted(VALID_MEM_MB))
        ttk.Label(
            frm,
            text=f"Memory cost (MB; opções: {mem_opts}):"
        ).grid(row=2, column=0, sticky="w", padx=5, pady=2)

        ttk.Combobox(frm, values=sorted(VALID_MEM_MB), textvariable=mem_var, state="readonly", width=5)\
           .grid(row=2, column=1)
        ttk.Label(
            frm,
            text=f"Parallelism (threads; {MIN_PARALLELISM}–{MAX_PARALLELISM}):"
        ).grid(row=3, column=0, sticky="w", padx=5, pady=2)

        tk.Spinbox(frm, from_=MIN_PARALLELISM, to=MAX_PARALLELISM, textvariable=par_var, width=5).grid(row=3, column=1)
        ttk.Label(frm, text="Hash: 256 bits").grid(row=4, column=0, columnspan=2, sticky="w", padx=5, pady=4)

    def _toggle_pw_e(self):
        if self.e_pw_e.cget("show") == "":
            self.e_pw_e.config(show="*"); self.btn_show_e.config(text="Mostrar")
        else:
            self.e_pw_e.config(show=""); self.btn_show_e.config(text="Ocultar")

    def _toggle_pw_d(self):
        if self.e_pw_d.cget("show") == "":
            self.e_pw_d.config(show="*"); self.btn_show_d.config(text="Mostrar")
        else:
            self.e_pw_d.config(show=""); self.btn_show_d.config(text="Ocultar")

    def _run_encrypt(self):
        if not all([self.png_in.get(), self.txt_in.get(), self.png_out.get(), self.pw_e.get()]):
            return messagebox.showerror("Erro", "Preencha todos os campos")
        salt = self.arg_salt.get()
        tc = self.arg_time.get()
        mb = int(self.arg_mem.get())
        par = self.arg_par.get()

        parent, child = Pipe(False)
        ticks = {"done": False, "count": 0, "total": 1}

        def poll():
            try:
                while parent.poll():
                    evt, *rest = parent.recv()
                    if evt == "start":
                        ticks["total"] = max(1, rest[0] // 1000)
                        ticks["count"] = 0
                    elif evt == "tick":
                        ticks["count"] += 1
                    elif evt == "done":
                        ticks["done"] = True
                    pct = min(100, int(100 * ticks["count"] / ticks["total"]))
                    self.pr_lbl_e.config(text=f"{pct}%")
            except (BrokenPipeError, EOFError):
                pass
            if not ticks["done"]:
                self.after(50, poll)

        fut = self.executor.submit(
            embed_message, self.png_in.get(), self.png_out.get(),
            self.txt_in.get(), self.pw_e.get(),
            salt, tc, mb, par, child
        )
        fut.add_done_callback(lambda f: self.after(0, self._on_enc_done, f))
        poll()

    def _on_enc_done(self, fut):
        try:
            fut.result()
            messagebox.showinfo("BitShadow", "Encriptado com sucesso!")
        except Exception as e:
            messagebox.showerror("Erro", str(e))
        finally:
            self.pr_lbl_e.config(text="0%")

    def _run_decrypt(self):
        if not all([self.png_in_dec.get(), self.txt_out.get(), self.pw_d.get()]):
            return messagebox.showerror("Erro", "Preencha todos os campos")
        tc = self.arg_time_d.get()
        mb = int(self.arg_mem_d.get())
        par = self.arg_par_d.get()

        parent, child = Pipe(False)
        ticks = {"done": False, "count": 0, "total": 1}

        def poll():
            try:
                while parent.poll():
                    evt, *rest = parent.recv()
                    if evt == "start":
                        ticks["total"] = max(1, rest[0] // 1000)
                        ticks["count"] = 0
                    elif evt == "tick":
                        ticks["count"] += 1
                    elif evt == "done":
                        ticks["done"] = True
                        ticks["count"] = ticks["total"]
                    pct = min(100, int(100 * ticks["count"] / ticks["total"]))
                    self.pr_lbl_d.config(text=f"{pct}%")
            except (BrokenPipeError, EOFError):
                pass
            if not ticks["done"]:
                self.after(50, poll)

        fut = self.executor.submit(
            extract_message, self.png_in_dec.get(), self.txt_out.get(),
            self.pw_d.get(), tc, mb, par, child
        )
        fut.add_done_callback(lambda f: self.after(0, self._on_dec_done, f))
        poll()

    def _on_dec_done(self, fut):
        try:
            fut.result()
            messagebox.showinfo("BitShadow", "Mensagem extraída com sucesso!")
        except Exception as e:
            messagebox.showerror("Erro", str(e))
        finally:
            self.pr_lbl_d.config(text="0%")

    def _auto_detect(self):
        p = self.png_in_dec.get()
        if os.path.exists(p):
            ok = detect_message(
                p, self.pw_d.get(),
                self.arg_time_d.get(),
                int(self.arg_mem_d.get()),
                self.arg_par_d.get()
            )
            msg = "Arquivo Oculto Detectado." if ok else "Não há nada na foto."
            self.lbl_dt.config(text=msg)
            messagebox.showinfo("BitShadow", msg)

if __name__ == "__main__":
    import multiprocessing
    multiprocessing.freeze_support()
    app = BitShadowApp()
    app.mainloop()