import os
import tempfile
import threading
import traceback
import tkinter as tk
from tkinter import filedialog, messagebox, ttk

from key_handler import load_private_key, load_public_key
from rsa_oaep import file_decrypt, file_encrypt, generate_and_save_keys


PROTOCOLS = {
    "textbook": "Textbook",
    "crt": "CRT",
    "precalc": "Precalc",
}

KEY_FILETYPES = (
    ("Hex key file", "*.hex"),
    ("Text file", "*.txt"),
    ("All files", "*.*"),
)


class RSAOAEPGUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("RSA-256 OAEP File Encryption")
        self.geometry("820x620")
        self.minsize(760, 560)

        self.busy = False
        self.action_buttons = []
        self.status_var = tk.StringVar(value="Siap.")

        self._build_styles()
        self._build_layout()

    def _build_styles(self):
        self.columnconfigure(0, weight=1)
        self.rowconfigure(0, weight=1)

        style = ttk.Style(self)
        style.configure("TButton", padding=(10, 5))
        style.configure("Primary.TButton", padding=(10, 5))
        style.configure("Section.TLabelframe", padding=10)

    def _build_layout(self):
        notebook = ttk.Notebook(self)
        notebook.grid(row=0, column=0, sticky="nsew", padx=12, pady=(12, 8))

        encrypt_tab = ttk.Frame(notebook, padding=12)
        decrypt_tab = ttk.Frame(notebook, padding=12)
        keygen_tab = ttk.Frame(notebook, padding=12)

        notebook.add(encrypt_tab, text="Encrypt")
        notebook.add(decrypt_tab, text="Decrypt")
        notebook.add(keygen_tab, text="Generate Key")

        self._build_encrypt_tab(encrypt_tab)
        self._build_decrypt_tab(decrypt_tab)
        self._build_keygen_tab(keygen_tab)

        status_bar = ttk.Label(self, textvariable=self.status_var, anchor="w")
        status_bar.grid(row=1, column=0, sticky="ew", padx=12, pady=(0, 10))

    def _build_encrypt_tab(self, parent):
        parent.columnconfigure(1, weight=1)

        self.enc_input_var = tk.StringVar()
        self.enc_output_var = tk.StringVar()
        self.enc_protocol_var = tk.StringVar(value="crt")
        self.enc_public_key_file_var = tk.StringVar()

        self._path_row(
            parent,
            row=0,
            label="File plaintext",
            variable=self.enc_input_var,
            button_text="Upload File",
            command=lambda: self._choose_open_file(
                self.enc_input_var,
                on_selected=lambda path: self._set_default_output(
                    path,
                    self.enc_output_var,
                    ".enc",
                ),
            ),
        )
        self._path_row(
            parent,
            row=1,
            label="Output ciphertext",
            variable=self.enc_output_var,
            button_text="Simpan Sebagai",
            command=lambda: self._choose_save_file(
                self.enc_output_var,
                default_ext=".enc",
                filetypes=(("Encrypted file", "*.enc"), ("All files", "*.*")),
            ),
        )

        ttk.Label(parent, text="Algoritma").grid(row=2, column=0, sticky="w", pady=6)
        ttk.Combobox(
            parent,
            textvariable=self.enc_protocol_var,
            values=list(PROTOCOLS.keys()),
            state="readonly",
            width=18,
        ).grid(row=2, column=1, sticky="w", pady=6)

        ttk.Label(
            parent,
            text="Peringatan: algoritma yang dipakai untuk dekripsi harus sesuai dengan algoritma enkripsi.",
            wraplength=650,
        ).grid(row=3, column=0, columnspan=3, sticky="w", pady=(4, 10))

        key_frame = ttk.LabelFrame(parent, text="Public Key untuk Encrypt", padding=10)
        key_frame.grid(row=4, column=0, columnspan=3, sticky="ew", pady=(0, 10))
        key_frame.columnconfigure(1, weight=1)

        ttk.Label(key_frame, text="File key").grid(
            row=0, column=0, sticky="w", pady=(0, 6)
        )
        ttk.Entry(key_frame, textvariable=self.enc_public_key_file_var).grid(
            row=0,
            column=1,
            sticky="ew",
            padx=(8, 8),
            pady=(0, 6),
        )
        ttk.Button(
            key_frame,
            text="Upload Public Key",
            command=self._load_public_key_file,
        ).grid(row=0, column=2, pady=(0, 6))

        encrypt_button = ttk.Button(
            parent,
            text="Encrypt File",
            style="Primary.TButton",
            command=self._start_encrypt,
        )
        encrypt_button.grid(row=5, column=2, sticky="e")
        self.action_buttons.append(encrypt_button)

    def _build_decrypt_tab(self, parent):
        parent.columnconfigure(1, weight=1)

        self.dec_input_var = tk.StringVar()
        self.dec_output_var = tk.StringVar()
        self.dec_private_key_var = tk.StringVar()
        self.dec_protocol_var = tk.StringVar(value="crt")

        self._path_row(
            parent,
            row=0,
            label="File ciphertext",
            variable=self.dec_input_var,
            button_text="Upload File",
            command=lambda: self._choose_open_file(
                self.dec_input_var,
                on_selected=lambda path: self._set_default_decrypt_output(path),
                filetypes=(("Encrypted file", "*.enc"), ("All files", "*.*")),
            ),
        )
        self._path_row(
            parent,
            row=1,
            label="Private key",
            variable=self.dec_private_key_var,
            button_text="Upload Private Key",
            command=self._load_private_key_file,
        )
        self._path_row(
            parent,
            row=2,
            label="Output plaintext",
            variable=self.dec_output_var,
            button_text="Simpan Sebagai",
            command=lambda: self._choose_save_file(self.dec_output_var),
        )

        ttk.Label(parent, text="Algoritma").grid(row=3, column=0, sticky="w", pady=6)
        ttk.Combobox(
            parent,
            textvariable=self.dec_protocol_var,
            values=list(PROTOCOLS.keys()),
            state="readonly",
            width=18,
        ).grid(row=3, column=1, sticky="w", pady=6)

        help_text = "Peringatan: algoritma yang dipakai untuk dekripsi harus sesuai dengan algoritma enkripsi. "
        ttk.Label(parent, text=help_text, wraplength=650).grid(
            row=4,
            column=0,
            columnspan=3,
            sticky="w",
            pady=(8, 16),
        )

        decrypt_button = ttk.Button(
            parent,
            text="Decrypt File",
            style="Primary.TButton",
            command=self._start_decrypt,
        )
        decrypt_button.grid(row=5, column=2, sticky="e")
        self.action_buttons.append(decrypt_button)

    def _build_keygen_tab(self, parent):
        parent.columnconfigure(1, weight=1)

        self.keygen_protocol_var = tk.StringVar(value="crt")
        self.keygen_public_path_var = tk.StringVar(value="public_key.hex")
        self.keygen_private_path_var = tk.StringVar(value="private_key.hex")

        ttk.Label(parent, text="Algoritma").grid(row=0, column=0, sticky="w", pady=6)
        ttk.Combobox(
            parent,
            textvariable=self.keygen_protocol_var,
            values=list(PROTOCOLS.keys()),
            state="readonly",
            width=18,
        ).grid(row=0, column=1, sticky="w", pady=6)

        self._path_row(
            parent,
            row=1,
            label="Public key output",
            variable=self.keygen_public_path_var,
            button_text="Pilih Lokasi",
            command=lambda: self._choose_save_file(
                self.keygen_public_path_var,
                default_ext=".hex",
                filetypes=KEY_FILETYPES,
            ),
        )
        self._path_row(
            parent,
            row=2,
            label="Private key output",
            variable=self.keygen_private_path_var,
            button_text="Pilih Lokasi",
            command=lambda: self._choose_save_file(
                self.keygen_private_path_var,
                default_ext=".hex",
                filetypes=KEY_FILETYPES,
            ),
        )

        ttk.Label(
            parent,
            text="Generate key 2048-bit dapat memakan waktu, terutama untuk CRT dan Precalc.",
            wraplength=650,
        ).grid(row=3, column=0, columnspan=3, sticky="w", pady=(8, 16))

        keygen_button = ttk.Button(
            parent,
            text="Generate Key Pair",
            style="Primary.TButton",
            command=self._start_keygen,
        )
        keygen_button.grid(row=4, column=2, sticky="e")
        self.action_buttons.append(keygen_button)

    def _path_row(self, parent, row, label, variable, button_text, command):
        ttk.Label(parent, text=label).grid(row=row, column=0, sticky="w", pady=6)
        ttk.Entry(parent, textvariable=variable).grid(
            row=row,
            column=1,
            sticky="ew",
            padx=(8, 8),
            pady=6,
        )
        ttk.Button(parent, text=button_text, command=command).grid(
            row=row, column=2, pady=6
        )

    def _add_text_scrollbars(self, parent, text_widget, row, column):
        scrollbar_y = ttk.Scrollbar(
            parent, orient="vertical", command=text_widget.yview
        )
        scrollbar_y.grid(row=row, column=column, sticky="ns")
        text_widget.configure(yscrollcommand=scrollbar_y.set)

    def _choose_open_file(
        self, variable, on_selected=None, filetypes=(("All files", "*.*"),)
    ):
        path = filedialog.askopenfilename(filetypes=filetypes)
        if not path:
            return
        variable.set(path)
        if on_selected:
            on_selected(path)

    def _choose_save_file(
        self, variable, default_ext="", filetypes=(("All files", "*.*"),)
    ):
        path = filedialog.asksaveasfilename(
            defaultextension=default_ext, filetypes=filetypes
        )
        if path:
            variable.set(path)

    def _set_default_output(self, input_path, output_var, suffix):
        if input_path and not output_var.get().strip():
            output_var.set(input_path + suffix)

    def _set_default_decrypt_output(self, input_path):
        if not input_path or self.dec_output_var.get().strip():
            return
        if input_path.endswith(".enc"):
            self.dec_output_var.set(input_path[:-4])
        else:
            self.dec_output_var.set(input_path + ".dec")

    def _load_public_key_file(self):
        path = filedialog.askopenfilename(filetypes=KEY_FILETYPES)
        if not path:
            return

        try:
            protocol = self._read_key_protocol(path)
        except Exception as exc:
            messagebox.showerror("Public key tidak valid", str(exc))
            return

        self.enc_public_key_file_var.set(path)
        if protocol:
            self.enc_protocol_var.set(protocol)
        self.status_var.set(f"Public key dimuat: {os.path.basename(path)}")

    def _load_private_key_file(self):
        path = filedialog.askopenfilename(filetypes=KEY_FILETYPES)
        if not path:
            return

        try:
            protocol = self._read_key_protocol(path)
        except Exception as exc:
            messagebox.showerror("Private key tidak valid", str(exc))
            return

        self.dec_private_key_var.set(path)
        if protocol:
            self.dec_protocol_var.set(protocol)
        self.status_var.set(f"Private key dimuat: {os.path.basename(path)}")

    def _start_encrypt(self):
        plaintext_file = self.enc_input_var.get().strip()
        output_file = self.enc_output_var.get().strip()
        public_key_file = self.enc_public_key_file_var.get().strip()
        protocol = self.enc_protocol_var.get()

        if not plaintext_file:
            messagebox.showwarning(
                "Data belum lengkap", "Pilih file plaintext terlebih dahulu."
            )
            return
        if not output_file:
            messagebox.showwarning(
                "Data belum lengkap", "Pilih lokasi output ciphertext."
            )
            return
        if not public_key_file:
            messagebox.showwarning(
                "Data belum lengkap", "Upload public key terlebih dahulu."
            )
            return

        def task():
            temp_key_path = None
            try:
                temp_key_path = self._prepare_key_file(
                    public_key_file, protocol, "public"
                )
                file_encrypt(
                    plaintext_file, temp_key_path or public_key_file, output_file
                )
            finally:
                if temp_key_path and os.path.exists(temp_key_path):
                    os.remove(temp_key_path)

        self._run_worker(
            "Encrypt", task, f"File berhasil dienkripsi ke:\n{output_file}"
        )

    def _start_decrypt(self):
        ciphertext_file = self.dec_input_var.get().strip()
        private_key_file = self.dec_private_key_var.get().strip()
        output_file = self.dec_output_var.get().strip()
        selected_protocol = self.dec_protocol_var.get()

        if not ciphertext_file:
            messagebox.showwarning(
                "Data belum lengkap", "Pilih file ciphertext terlebih dahulu."
            )
            return
        if not private_key_file:
            messagebox.showwarning(
                "Data belum lengkap", "Upload private key terlebih dahulu."
            )
            return
        if not output_file:
            messagebox.showwarning(
                "Data belum lengkap", "Pilih lokasi output plaintext."
            )
            return

        def task():
            temp_key_path = None
            try:
                temp_key_path = self._prepare_key_file(
                    private_key_file, selected_protocol, "private"
                )
                file_decrypt(
                    ciphertext_file, temp_key_path or private_key_file, output_file
                )
            finally:
                if temp_key_path and os.path.exists(temp_key_path):
                    os.remove(temp_key_path)

        self._run_worker(
            "Decrypt", task, f"File berhasil didekripsi ke:\n{output_file}"
        )

    def _start_keygen(self):
        public_key_path = self.keygen_public_path_var.get().strip()
        private_key_path = self.keygen_private_path_var.get().strip()
        protocol = self.keygen_protocol_var.get()

        if not public_key_path:
            messagebox.showwarning(
                "Data belum lengkap", "Pilih lokasi output public key."
            )
            return
        if not private_key_path:
            messagebox.showwarning(
                "Data belum lengkap", "Pilih lokasi output private key."
            )
            return

        def task():
            generate_and_save_keys(public_key_path, private_key_path, protocol)

        self._run_worker(
            "Generate key",
            task,
            "Key pair berhasil dibuat:\n"
            f"Public: {public_key_path}\n"
            f"Private: {private_key_path}",
        )

    def _prepare_key_file(self, key_path, selected_protocol, key_type):
        embedded_protocol = self._read_key_protocol(key_path)
        if embedded_protocol and embedded_protocol != selected_protocol:
            raise ValueError(
                "Algoritma yang dipilih tidak sama dengan algoritma key "
                f"({selected_protocol} != {embedded_protocol})."
            )

        if embedded_protocol:
            return None

        with open(key_path, "r") as key_file:
            key_text = key_file.read()

        normalized_key = self._normalize_key_text(key_text, selected_protocol)
        temp_key = tempfile.NamedTemporaryFile(
            "w", delete=False, suffix=f".{key_type}_key.hex"
        )
        try:
            temp_key.write(normalized_key)
            temp_key_path = temp_key.name
        finally:
            temp_key.close()

        try:
            if key_type == "public":
                load_public_key(temp_key_path)
            else:
                load_private_key(temp_key_path)
        except Exception:
            os.remove(temp_key_path)
            raise

        return temp_key_path

    def _normalize_key_text(self, key_text, selected_protocol):
        lines = [line.strip() for line in key_text.splitlines() if line.strip()]
        if not lines:
            raise ValueError("File key kosong.")

        protocol_line_index = None
        embedded_protocol = None
        for index, line in enumerate(lines):
            if line.startswith("protocol="):
                protocol_line_index = index
                embedded_protocol = line.split("=", 1)[1].strip()
                break

        if embedded_protocol and embedded_protocol not in PROTOCOLS:
            raise ValueError(f"Algoritma key tidak dikenal: {embedded_protocol}")

        if embedded_protocol and embedded_protocol != selected_protocol:
            raise ValueError(
                "Algoritma yang dipilih tidak sama dengan algoritma key "
                f"({selected_protocol} != {embedded_protocol})."
            )

        if protocol_line_index is None:
            lines.insert(0, f"protocol={selected_protocol}")

        return "\n".join(lines) + "\n"

    def _read_key_protocol(self, key_path):
        found_keys = set()
        with open(key_path, "r") as key_file:
            for line in key_file:
                key, separator, value = line.strip().partition("=")
                if not separator:
                    continue
                elif key == "protocol":
                    protocol = value.strip()
                    if protocol not in PROTOCOLS:
                        raise ValueError(f"Algoritma key tidak dikenal: {protocol}")
                    return protocol
                else:
                    found_keys.add(key)
        
        if any(key in found_keys for key in ["d0p", "d1p", "h"]):
            return "precalc"
        elif any(key in found_keys for key in ["dp", "dq"]):
            return "crt"
        elif any(key in found_keys for key in ["d", "n"]):
            return "textbook"
        
        return None

    def _run_worker(self, action_name, task, success_message):
        if self.busy:
            messagebox.showinfo("Sedang berjalan", "Tunggu proses sebelumnya selesai.")
            return

        self._set_busy(True, f"{action_name} sedang berjalan...")

        def worker():
            try:
                task()
            except Exception as exc:
                details = traceback.format_exc()
                self.after(
                    0, lambda: self._show_worker_error(action_name, exc, details)
                )
            else:
                self.after(
                    0, lambda: self._show_worker_success(action_name, success_message)
                )

        threading.Thread(target=worker, daemon=True).start()

    def _show_worker_success(self, action_name, message):
        self._set_busy(False, f"{action_name} selesai.")
        messagebox.showinfo(f"{action_name} berhasil", message)

    def _show_worker_error(self, action_name, exc, details):
        self._set_busy(False, f"{action_name} gagal.")
        print(details)
        messagebox.showerror(f"{action_name} gagal", str(exc))

    def _set_busy(self, busy, status):
        self.busy = busy
        self.status_var.set(status)
        state = "disabled" if busy else "normal"
        for button in self.action_buttons:
            button.configure(state=state)


def main():
    app = RSAOAEPGUI()
    app.mainloop()


if __name__ == "__main__":
    main()
