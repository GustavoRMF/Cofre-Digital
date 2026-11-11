# -*- coding: utf-8 -*-
"""
Cofre Digital V4.2.0 - Security 3D Multi-Cadastro
Interface: HTML + CSS + JavaScript (renderizada com pywebview)
Backend: Python + AES-GCM + PBKDF2-SHA256

Novidades da V4.2.0:
- Visualizador de arquivos integrado (imagens, PDF, texto/código, áudio e vídeo).
  Os arquivos são descriptografados SOMENTE em memória; nada é gravado em disco.
- Navegação entre arquivos (setas do teclado), zoom de imagens e atalho Esc.
- Troca de senha sem gravar texto puro no disco durante a recriptografia.
- Proteção contra injeção de HTML pelo nome do cadastro e contra IDs de perfil
  malformados (path traversal).
- Bloqueio de login/cadastro enquanto outro cofre estiver aberto.
- Duplo clique agora abre o visualizador (a seleção não recria mais a tabela).

Compatibilidade:
- Mantém a pasta ~/CofreDigital usada pelas versões anteriores.
- Lê índices V2, V3 e V4.
"""

import os
import sys
import json
import base64
import hashlib
import secrets
import shutil
import tempfile
import threading
import atexit
import subprocess
from datetime import datetime

import webview
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# ============================================================
# CONFIGURAÇÕES
# ============================================================

APP_NAME = "Cofre Digital"
APP_VERSION = "4.2.0"

BASE_DIR = os.path.join(os.path.expanduser("~"), "CofreDigital")
PROFILES_DIR = os.path.join(BASE_DIR, "perfis")
USERS_FILE = os.path.join(BASE_DIR, "cadastros.json")

# Caminhos da versão de cadastro único. Eles permanecem intactos para que o
# cofre já existente seja preservado como "Cadastro Principal".
LEGACY_VAULT_DIR = os.path.join(BASE_DIR, "vault")
LEGACY_TEMP_DIR = os.path.join(BASE_DIR, "temp")
LEGACY_DATA_FILE = os.path.join(BASE_DIR, "cofre.dat")
LEGACY_INDEX_FILE = os.path.join(BASE_DIR, "indice.dat")

# O perfil ativo altera estes caminhos em tempo de execução. Dessa forma, todo
# o restante do mecanismo de criptografia continua usando arquivos isolados.
VAULT_DIR = LEGACY_VAULT_DIR
TEMP_DIR = LEGACY_TEMP_DIR
DATA_FILE = LEGACY_DATA_FILE
INDEX_FILE = LEGACY_INDEX_FILE

PBKDF2_ITERATIONS = 600_000
KEY_SIZE = 32
SALT_SIZE = 16
NONCE_SIZE = 12
TAG_SIZE = 16

VERIFICATION_TEXT = b"COFRE_DIGITAL_OK"
INDEX_TEXT_V4 = b"COFRE_DIGITAL_INDEX_V4"
INDEX_PREFIXES = (
    b"COFRE_DIGITAL_INDEX_V4\n",
    b"COFRE_DIGITAL_INDEX_V3\n",
    b"COFRE_DIGITAL_INDEX_V2\n",
)

# Visualizador
PREVIEW_MAX_BYTES = 30 * 1024 * 1024      # limite do arquivo original para visualização
TEXT_PREVIEW_LIMIT = 1_000_000            # máximo de caracteres exibidos em texto

IMAGE_TYPES = {
    "png": "image/png",
    "jpg": "image/jpeg",
    "jpeg": "image/jpeg",
    "jfif": "image/jpeg",
    "gif": "image/gif",
    "webp": "image/webp",
    "bmp": "image/bmp",
    "svg": "image/svg+xml",
    "ico": "image/x-icon",
    "avif": "image/avif",
}
AUDIO_TYPES = {
    "mp3": "audio/mpeg",
    "wav": "audio/wav",
    "ogg": "audio/ogg",
    "oga": "audio/ogg",
    "opus": "audio/ogg",
    "m4a": "audio/mp4",
    "aac": "audio/aac",
    "flac": "audio/flac",
}
VIDEO_TYPES = {
    "mp4": "video/mp4",
    "m4v": "video/mp4",
    "mov": "video/mp4",
    "webm": "video/webm",
    "ogv": "video/ogg",
}
TEXT_EXTENSIONS = {
    "txt", "md", "markdown", "log", "json", "csv", "tsv", "xml", "html", "htm",
    "css", "js", "mjs", "ts", "tsx", "jsx", "py", "java", "c", "cpp", "h", "hpp",
    "cs", "go", "rs", "php", "rb", "sh", "bat", "cmd", "ps1", "sql", "ini", "cfg",
    "conf", "yaml", "yml", "toml", "tex", "srt", "vtt", "env", "gitignore", "kt",
    "swift", "lua", "r", "m", "dart", "vue", "svelte", "properties",
}

WINDOW = None

SAFE_ID_CHARS = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_")


# ============================================================
# UTILITÁRIOS
# ============================================================

def ensure_directories():
    os.makedirs(BASE_DIR, exist_ok=True)
    os.makedirs(PROFILES_DIR, exist_ok=True)
    os.makedirs(VAULT_DIR, exist_ok=True)
    os.makedirs(TEMP_DIR, exist_ok=True)


def _safe_profile_id(profile_id) -> str:
    """Aceita apenas IDs formados por letras, números, '-' e '_'."""
    pid = str(profile_id or "").strip()
    if pid and all(ch in SAFE_ID_CHARS for ch in pid):
        return pid
    return ""


def _profile_public(profile: dict) -> dict:
    return {
        "id": str(profile.get("id", "")),
        "username": str(profile.get("username", "Cadastro")),
        "legacy": bool(profile.get("legacy", False)),
    }


def _profile_paths(profile: dict) -> dict:
    if profile.get("legacy"):
        root = BASE_DIR
        return {
            "root": root,
            "vault": LEGACY_VAULT_DIR,
            "temp": LEGACY_TEMP_DIR,
            "data": LEGACY_DATA_FILE,
            "index": LEGACY_INDEX_FILE,
        }

    profile_id = _safe_profile_id(profile.get("id"))
    if not profile_id:
        raise ValueError("Identificador de cadastro inválido.")

    root = os.path.join(PROFILES_DIR, profile_id)
    return {
        "root": root,
        "vault": os.path.join(root, "vault"),
        "temp": os.path.join(root, "temp"),
        "data": os.path.join(root, "cofre.dat"),
        "index": os.path.join(root, "indice.dat"),
    }


def activate_profile(profile: dict):
    global VAULT_DIR, TEMP_DIR, DATA_FILE, INDEX_FILE
    paths = _profile_paths(profile)
    VAULT_DIR = paths["vault"]
    TEMP_DIR = paths["temp"]
    DATA_FILE = paths["data"]
    INDEX_FILE = paths["index"]
    os.makedirs(paths["root"], exist_ok=True)
    os.makedirs(VAULT_DIR, exist_ok=True)
    os.makedirs(TEMP_DIR, exist_ok=True)
    return paths


def save_profiles(profiles: list):
    clean = []
    for p in profiles:
        clean.append({
            "id": str(p.get("id", "")),
            "username": str(p.get("username", "Cadastro")),
            "legacy": bool(p.get("legacy", False)),
            "created_at": str(p.get("created_at", "")),
        })
    atomic_write_text(USERS_FILE, json.dumps(clean, ensure_ascii=False, indent=2))


def load_profiles() -> list:
    os.makedirs(BASE_DIR, exist_ok=True)
    os.makedirs(PROFILES_DIR, exist_ok=True)
    profiles = []

    if os.path.exists(USERS_FILE):
        try:
            with open(USERS_FILE, "r", encoding="utf-8") as f:
                raw = json.load(f)
            if isinstance(raw, list):
                for p in raw:
                    if isinstance(p, dict) and p.get("id") and p.get("username"):
                        profiles.append(p)
        except Exception:
            profiles = []

    # Recupera perfis novos pelo arquivo profile.json caso o cadastro geral
    # tenha sido removido ou danificado.
    known_ids = {str(p.get("id")) for p in profiles}
    try:
        for name in os.listdir(PROFILES_DIR):
            root = os.path.join(PROFILES_DIR, name)
            meta = os.path.join(root, "profile.json")
            if name in known_ids or not os.path.isdir(root) or not os.path.exists(meta):
                continue
            try:
                with open(meta, "r", encoding="utf-8") as f:
                    p = json.load(f)
                if isinstance(p, dict) and p.get("id") and p.get("username"):
                    p["legacy"] = False
                    profiles.append(p)
                    known_ids.add(str(p.get("id")))
            except Exception:
                pass
    except Exception:
        pass

    # Migração sem mover nem recriptografar o cofre antigo.
    if os.path.exists(LEGACY_DATA_FILE) and not any(p.get("legacy") for p in profiles):
        profiles.insert(0, {
            "id": "legacy-principal",
            "username": "Cadastro Principal",
            "legacy": True,
            "created_at": "Versão anterior",
        })

    # Remove duplicidades de ID, IDs inseguros e garante nomes exibíveis.
    result = []
    seen = set()
    for p in profiles:
        pid = _safe_profile_id(p.get("id"))
        username = str(p.get("username", "")).strip()
        if not pid or not username or pid in seen:
            continue
        seen.add(pid)
        p["id"] = pid
        p["username"] = username[:40]
        result.append(p)

    # Persiste a migração/recuperação.
    try:
        save_profiles(result)
    except Exception:
        pass
    return result


def find_profile(profile_id: str):
    wanted = str(profile_id or "").strip()
    for profile in load_profiles():
        if str(profile.get("id")) == wanted:
            return profile
    return None


def validate_username(username: str):
    name = " ".join(str(username or "").strip().split())
    if len(name) < 2:
        return None, "Informe um nome para o cadastro com pelo menos 2 caracteres."
    if len(name) > 40:
        return None, "O nome do cadastro deve ter no máximo 40 caracteres."
    if any(ord(ch) < 32 for ch in name):
        return None, "O nome do cadastro contém caracteres inválidos."
    return name, None


def cleanup_temp():
    try:
        ensure_directories()
        for name in os.listdir(TEMP_DIR):
            path = os.path.join(TEMP_DIR, name)
            try:
                if os.path.isdir(path):
                    shutil.rmtree(path, ignore_errors=True)
                else:
                    os.remove(path)
            except Exception:
                pass
    except Exception:
        pass


def secure_random(size: int) -> bytes:
    return secrets.token_bytes(size)


def generate_vault_filename() -> str:
    return secrets.token_hex(32) + ".vault"


def now_text() -> str:
    return datetime.now().strftime("%d/%m/%Y %H:%M")


def format_size(size: int) -> str:
    units = ["B", "KB", "MB", "GB", "TB"]
    value = float(max(0, size))
    for unit in units:
        if value < 1024:
            return f"{value:.1f} {unit}"
        value /= 1024
    return f"{value:.1f} PB"


def get_file_ext(name) -> str:
    return os.path.splitext(str(name or ""))[1].lower().lstrip(".")


def json_for_html(obj) -> str:
    """
    Serializa JSON de forma segura para ser inserido dentro de <script>.
    Evita que textos como '</script>' no nome do cadastro quebrem a página.
    """
    text = json.dumps(obj, ensure_ascii=False)
    return (
        text.replace("&", "\\u0026")
        .replace("<", "\\u003c")
        .replace(">", "\\u003e")
        .replace("\u2028", "\\u2028")
        .replace("\u2029", "\\u2029")
    )


def atomic_write_text(path: str, text: str):
    folder = os.path.dirname(path)
    os.makedirs(folder, exist_ok=True)
    fd, temp_path = tempfile.mkstemp(prefix=".tmp_", dir=folder)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(text)
            f.flush()
            os.fsync(f.fileno())
        os.replace(temp_path, path)
    except Exception:
        try:
            os.remove(temp_path)
        except Exception:
            pass
        raise


def atomic_write_bytes(path: str, data: bytes):
    folder = os.path.dirname(path)
    os.makedirs(folder, exist_ok=True)
    fd, temp_path = tempfile.mkstemp(prefix=".tmp_", dir=folder)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(temp_path, path)
    except Exception:
        try:
            os.remove(temp_path)
        except Exception:
            pass
        raise


# ============================================================
# SENHA / CHAVE
# ============================================================

def derive_key(password: str, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac(
        "sha256",
        password.encode("utf-8"),
        salt,
        PBKDF2_ITERATIONS,
        dklen=KEY_SIZE,
    )


def save_config(salt: bytes, verification: bytes):
    data = {
        "version": 4,
        "salt": base64.b64encode(salt).decode("ascii"),
        "verification": base64.b64encode(verification).decode("ascii"),
    }
    atomic_write_text(DATA_FILE, json.dumps(data, ensure_ascii=False))


def load_config():
    if not os.path.exists(DATA_FILE):
        return None

    try:
        with open(DATA_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)

        return (
            base64.b64decode(data["salt"]),
            base64.b64decode(data["verification"]),
        )
    except Exception:
        return None


def make_verification(key: bytes) -> bytes:
    nonce = secure_random(NONCE_SIZE)
    encrypted = AESGCM(key).encrypt(nonce, VERIFICATION_TEXT, None)
    return nonce + encrypted


def unlock_key(password: str):
    """
    Deriva a chave a partir da senha e confirma se ela está correta.
    Retorna a chave (bytes) ou None. Executa o PBKDF2 uma única vez.
    """
    config = load_config()
    if not config:
        return None

    salt, verification = config

    try:
        key = derive_key(password, salt)
        nonce = verification[:NONCE_SIZE]
        encrypted = verification[NONCE_SIZE:]
        result = AESGCM(key).decrypt(nonce, encrypted, None)
        if result == VERIFICATION_TEXT:
            return key
    except Exception:
        pass
    return None


def check_password(password: str) -> bool:
    return unlock_key(password) is not None


def get_key_from_password(password: str):
    return unlock_key(password)


def create_vault_config(password: str):
    salt = secure_random(SALT_SIZE)
    key = derive_key(password, salt)
    verification = make_verification(key)
    save_config(salt, verification)
    save_index(key, [])
    return key


# ============================================================
# CRIPTOGRAFIA DE ARQUIVOS
# ============================================================

def encrypt_bytes(data: bytes, key: bytes) -> bytes:
    nonce = secure_random(NONCE_SIZE)
    return nonce + AESGCM(key).encrypt(nonce, data, None)


def decrypt_bytes(source: str, key: bytes) -> bytes:
    """Lê um arquivo .vault e devolve o conteúdo original (somente em memória)."""
    with open(source, "rb") as f:
        data = f.read()

    if len(data) < NONCE_SIZE + TAG_SIZE:
        raise ValueError("Arquivo criptografado inválido.")

    nonce = data[:NONCE_SIZE]
    encrypted = data[NONCE_SIZE:]
    return AESGCM(key).decrypt(nonce, encrypted, None)


def encrypt_file(source: str, destination: str, key: bytes):
    with open(source, "rb") as f:
        data = f.read()

    atomic_write_bytes(destination, encrypt_bytes(data, key))


def decrypt_file(source: str, destination: str, key: bytes):
    atomic_write_bytes(destination, decrypt_bytes(source, key))


# ============================================================
# ÍNDICE CRIPTOGRAFADO
# ============================================================

def save_index(key: bytes, items: list):
    nonce = secure_random(NONCE_SIZE)
    payload = json.dumps(items, ensure_ascii=False).encode("utf-8")
    plain = INDEX_TEXT_V4 + b"\n" + payload
    encrypted = AESGCM(key).encrypt(nonce, plain, None)
    atomic_write_bytes(INDEX_FILE, nonce + encrypted)


def load_index(key: bytes) -> list:
    if not os.path.exists(INDEX_FILE):
        return []

    try:
        with open(INDEX_FILE, "rb") as f:
            data = f.read()

        if len(data) < NONCE_SIZE + TAG_SIZE:
            return []

        nonce = data[:NONCE_SIZE]
        encrypted = data[NONCE_SIZE:]
        plain = AESGCM(key).decrypt(nonce, encrypted, None)

        payload = None
        for prefix in INDEX_PREFIXES:
            if plain.startswith(prefix):
                payload = plain[len(prefix):]
                break

        if payload is None:
            return []

        result = json.loads(payload.decode("utf-8"))
        return result if isinstance(result, list) else []
    except Exception:
        return []


def get_file_dialog_type(kind: str):
    """
    Compatibilidade com várias versões do pywebview.
    kind: 'open', 'save' ou 'folder'
    """
    fd = getattr(webview, "FileDialog", None)

    if fd is not None:
        candidates = {
            "open": ("OPEN", "LOAD"),
            "save": ("SAVE",),
            "folder": ("FOLDER",),
        }.get(kind, ())

        for name in candidates:
            value = getattr(fd, name, None)
            if value is not None:
                return value

    legacy = {
        "open": ("OPEN_DIALOG",),
        "save": ("SAVE_DIALOG",),
        "folder": ("FOLDER_DIALOG",),
    }.get(kind, ())

    for name in legacy:
        value = getattr(webview, name, None)
        if value is not None:
            return value

    return None


# ============================================================
# VISUALIZAÇÃO DE ARQUIVOS (SOMENTE EM MEMÓRIA)
# ============================================================

def _looks_like_text(sample: bytes) -> bool:
    if not sample:
        return True
    if b"\x00" in sample:
        return False
    bad = sum(1 for b in sample if b < 9 or 14 <= b < 32)
    return (bad / len(sample)) < 0.01


def sniff_kind(data: bytes):
    """Identifica o tipo pelo conteúdo quando a extensão é desconhecida."""
    head = data[:16]

    if head.startswith(b"\x89PNG\r\n\x1a\n"):
        return "image", "image/png"
    if head.startswith(b"\xff\xd8\xff"):
        return "image", "image/jpeg"
    if head.startswith((b"GIF87a", b"GIF89a")):
        return "image", "image/gif"
    if head[:4] == b"RIFF" and head[8:12] == b"WEBP":
        return "image", "image/webp"
    if head.startswith(b"%PDF-"):
        return "pdf", "application/pdf"

    if _looks_like_text(data[:8192]):
        return "text", "text/plain"

    return None, None


def detect_preview_kind(name: str, data: bytes):
    ext = get_file_ext(name)

    if ext in IMAGE_TYPES:
        return "image", IMAGE_TYPES[ext]
    if ext in AUDIO_TYPES:
        return "audio", AUDIO_TYPES[ext]
    if ext in VIDEO_TYPES:
        return "video", VIDEO_TYPES[ext]
    if ext == "pdf":
        return "pdf", "application/pdf"
    if ext in TEXT_EXTENSIONS:
        return "text", "text/plain"

    return sniff_kind(data)


def decode_text_bytes(data: bytes) -> str:
    if data.startswith((b"\xff\xfe", b"\xfe\xff")):
        try:
            return data.decode("utf-16")
        except Exception:
            pass

    try:
        return data.decode("utf-8-sig")
    except Exception:
        pass

    try:
        return data.decode("cp1252")
    except Exception:
        return data.decode("latin-1", errors="replace")


def prepare_text_preview(name: str, data: bytes):
    text = decode_text_bytes(data)

    if get_file_ext(name) == "json" and len(text) <= 2_000_000:
        try:
            text = json.dumps(json.loads(text), ensure_ascii=False, indent=2)
        except Exception:
            pass

    truncated = len(text) > TEXT_PREVIEW_LIMIT
    if truncated:
        text = text[:TEXT_PREVIEW_LIMIT]

    return text, truncated


# ============================================================
# API PYTHON <-> JAVASCRIPT
# ============================================================

class VaultAPI:
    def __init__(self):
        self._window = None
        self.key = None
        self.password = None
        self.index = []
        self.current_profile = None
        self._lock = threading.RLock()

    def _set_window(self, window):
        # A referência da janela fica privada. Assim ela não é percorrida
        # pelo mecanismo de exposição da API JavaScript do pywebview.
        self._window = window

    def _ok(self, **kwargs):
        return {"ok": True, **kwargs}

    def _error(self, message: str, **kwargs):
        return {"ok": False, "message": message, **kwargs}

    def _require_login(self):
        return bool(self.key and self.current_profile)

    def _profiles_public(self):
        return [_profile_public(p) for p in load_profiles()]

    def _vault_path(self, vault_name):
        # basename impede que um nome malformado saia da pasta do cofre.
        return os.path.join(VAULT_DIR, os.path.basename(str(vault_name or "")))

    def get_state(self):
        with self._lock:
            profiles = self._profiles_public()
            return {
                "ok": True,
                "app_name": APP_NAME,
                "version": APP_VERSION,
                "configured": bool(profiles),
                "profiles": profiles,
                "logged_in": bool(self.key and self.current_profile),
                "current_user": _profile_public(self.current_profile) if self.current_profile else None,
                "base_dir": BASE_DIR,
            }

    def create_profile(self, username, password, confirm):
        with self._lock:
            if self._require_login():
                return self._error("Bloqueie o cofre atual antes de criar outro cadastro.")

            profile = None
            try:
                username, error = validate_username(username)
                if error:
                    return self._error(error)

                profiles = load_profiles()
                if any(str(p.get("username", "")).casefold() == username.casefold() for p in profiles):
                    return self._error("Já existe um cadastro com esse nome.")

                password = str(password or "")
                confirm = str(confirm or "")
                if len(password) < 8:
                    return self._error("Use uma senha com pelo menos 8 caracteres.")
                if password != confirm:
                    return self._error("As senhas não são iguais.")

                profile = {
                    "id": secrets.token_hex(12),
                    "username": username,
                    "legacy": False,
                    "created_at": now_text(),
                }
                paths = activate_profile(profile)
                if os.path.exists(DATA_FILE):
                    return self._error("Este cadastro já possui um cofre configurado.")

                self.key = create_vault_config(password)
                self.password = password
                self.index = []
                self.current_profile = profile

                atomic_write_text(
                    os.path.join(paths["root"], "profile.json"),
                    json.dumps(profile, ensure_ascii=False, indent=2),
                )
                profiles.append(profile)
                save_profiles(profiles)

                return self._ok(
                    message=f"Cadastro {username} criado com sucesso!",
                    profiles=self._profiles_public(),
                    current_user=_profile_public(profile),
                    stats=self._stats(),
                )
            except Exception as e:
                self.key = None
                self.password = None
                self.index = []
                self.current_profile = None
                if profile and not profile.get("legacy"):
                    try:
                        shutil.rmtree(_profile_paths(profile)["root"], ignore_errors=True)
                    except Exception:
                        pass
                return self._error(f"Não foi possível criar o cadastro: {e}")

    # Compatibilidade com chamadas antigas da interface V4.0.2.
    def create_vault(self, password, confirm):
        profiles = load_profiles()
        base_name = "Cadastro Principal" if not profiles else f"Cadastro {len(profiles) + 1}"
        return self.create_profile(base_name, password, confirm)

    def login(self, profile_id, password=None):
        with self._lock:
            if self._require_login():
                return self._error("Já existe um cofre aberto. Bloqueie-o antes de entrar em outro cadastro.")

            try:
                # Compatibilidade: versões antigas enviavam apenas a senha.
                if password is None:
                    password = profile_id
                    profiles = load_profiles()
                    if len(profiles) != 1:
                        return self._error("Selecione o cadastro para entrar.")
                    profile = profiles[0]
                else:
                    profile = find_profile(profile_id)

                if not profile:
                    return self._error("Cadastro não encontrado.")

                activate_profile(profile)
                password = str(password or "")
                key = unlock_key(password)
                if not key:
                    return self._error("Senha incorreta.")

                self.password = password
                self.key = key
                self.current_profile = profile

                loaded = load_index(self.key)
                recovered = self._recover_missing_entries(list(loaded))
                self.index = recovered
                if len(recovered) != len(loaded):
                    save_index(self.key, self.index)

                return self._ok(
                    message=f"Cofre de {profile.get('username')} desbloqueado.",
                    stats=self._stats(),
                    current_user=_profile_public(profile),
                )
            except Exception as e:
                self.key = None
                self.password = None
                self.index = []
                self.current_profile = None
                return self._error(f"Não foi possível desbloquear o cofre: {e}")

    def logout(self):
        with self._lock:
            cleanup_temp()
            self.key = None
            self.password = None
            self.index = []
            self.current_profile = None
            return self._ok(
                message="Cofre bloqueado.",
                profiles=self._profiles_public(),
            )

    def list_files(self):
        with self._lock:
            if not self._require_login():
                return self._error("O cofre está bloqueado.")

            try:
                before = len(self.index)
                self.index = self._recover_missing_entries(self.index)
                if len(self.index) != before:
                    save_index(self.key, self.index)

                items = []
                for item in self.index:
                    size = int(item.get("size", 0) or 0)
                    items.append({
                        "vault_name": item.get("vault_name", ""),
                        "name": item.get("name", "Arquivo protegido"),
                        "size": size,
                        "size_text": format_size(size),
                        "date": item.get("date", ""),
                        "type": item.get("type", "Arquivo"),
                    })

                items.sort(key=lambda x: str(x.get("name", "")).lower())
                return self._ok(items=items, stats=self._stats())
            except Exception as e:
                return self._error(f"Erro ao carregar arquivos: {e}")

    def add_files(self):
        if not self._require_login():
            return self._error("O cofre está bloqueado.")

        try:
            if not self._window:
                return self._error("Janela do aplicativo indisponível.")

            open_dialog_type = get_file_dialog_type("open")

            if open_dialog_type is None:
                # Algumas versões aceitam o diálogo padrão sem informar o tipo.
                files = self._window.create_file_dialog(allow_multiple=True)
            else:
                files = self._window.create_file_dialog(
                    open_dialog_type,
                    allow_multiple=True,
                )

            if not files:
                return self._ok(cancelled=True, message="Nenhum arquivo selecionado.")

            success = 0
            errors = []

            with self._lock:
                if not self._require_login():
                    return self._error("O cofre foi bloqueado durante a operação.")

                for source in files:
                    try:
                        if not os.path.isfile(source):
                            continue

                        filename = generate_vault_filename()
                        destination = os.path.join(VAULT_DIR, filename)

                        encrypt_file(source, destination, self.key)

                        original_name = os.path.basename(source)
                        extension = os.path.splitext(original_name)[1].lower()
                        file_type = extension[1:].upper() if extension else "Arquivo"

                        self.index.append({
                            "vault_name": filename,
                            "name": original_name,
                            "size": os.path.getsize(source),
                            "date": now_text(),
                            "type": file_type,
                        })
                        success += 1
                    except Exception as e:
                        errors.append(f"{os.path.basename(source)}: {e}")

                save_index(self.key, self.index)

            message = f"{success} arquivo(s) protegido(s)."
            if errors:
                message += f" {len(errors)} arquivo(s) apresentaram erro."

            return self._ok(
                message=message,
                success_count=success,
                errors=errors,
                stats=self._stats(),
            )
        except Exception as e:
            return self._error(f"Não foi possível adicionar os arquivos: {e}")

    def preview_file(self, vault_name):
        """
        Descriptografa o arquivo somente em memória e devolve o conteúdo
        para o visualizador. Nada é gravado em disco.
        """
        with self._lock:
            if not self._require_login():
                return self._error("O cofre está bloqueado.")

            item = self._find_item(vault_name)
            if not item:
                return self._error("Arquivo não encontrado no índice.")

            path = self._vault_path(item.get("vault_name"))
            if not os.path.exists(path):
                return self._error("O arquivo protegido não foi encontrado.")

            name = str(item.get("name", "Arquivo protegido"))
            base = {
                "name": name,
                "type": str(item.get("type", "Arquivo")),
                "size_text": format_size(int(item.get("size", 0) or 0)),
                "date": str(item.get("date", "")),
            }

            try:
                disk_size = os.path.getsize(path)
                if disk_size > PREVIEW_MAX_BYTES + NONCE_SIZE + TAG_SIZE:
                    return self._ok(
                        kind="too_large",
                        limit_text=format_size(PREVIEW_MAX_BYTES),
                        **base,
                    )

                data = decrypt_bytes(path, self.key)
            except Exception as e:
                return self._error(
                    f"Não foi possível descriptografar o arquivo para visualização: {e}"
                )

            kind, mime = detect_preview_kind(name, data)

            if kind == "text":
                text, truncated = prepare_text_preview(name, data)
                return self._ok(
                    kind="text",
                    text=text,
                    truncated=truncated,
                    chars=len(text),
                    **base,
                )

            if kind in ("image", "pdf", "audio", "video"):
                return self._ok(
                    kind=kind,
                    mime=mime,
                    data=base64.b64encode(data).decode("ascii"),
                    **base,
                )

            return self._ok(kind="unsupported", ext=get_file_ext(name), **base)

    def extract_file(self, vault_name):
        # Etapa 1: valida e localiza o arquivo.
        with self._lock:
            if not self._require_login():
                return self._error("O cofre está bloqueado.")

            item = self._find_item(vault_name)
            if not item:
                return self._error("Arquivo não encontrado no índice.")

            source = self._vault_path(item.get("vault_name"))
            if not os.path.exists(source):
                return self._error("O arquivo protegido não foi encontrado.")

            if not self._window:
                return self._error("Janela do aplicativo indisponível.")

            item_name = item.get("name", "arquivo_extraido")

        # Etapa 2: diálogos fora do lock, para não travar a interface.
        try:
            save_dialog_type = get_file_dialog_type("save")

            if save_dialog_type is None:
                return self._error(
                    "Sua versão do pywebview não oferece diálogo de salvar compatível. "
                    "Atualize com: python -m pip install -U pywebview"
                )

            destination = self._window.create_file_dialog(
                save_dialog_type,
                save_filename=item_name,
            )

            if not destination:
                return self._ok(cancelled=True, message="Extração cancelada.")

            if isinstance(destination, (tuple, list)):
                destination = destination[0]

            if os.path.exists(destination):
                try:
                    confirmed = self._window.create_confirmation_dialog(
                        "Substituir arquivo?",
                        "O arquivo escolhido já existe. Deseja substituí-lo?",
                    )
                except Exception:
                    confirmed = False

                if not confirmed:
                    return self._ok(cancelled=True, message="Extração cancelada.")

            # Etapa 3: descriptografa.
            with self._lock:
                if not self._require_login():
                    return self._error("O cofre foi bloqueado durante a operação.")
                decrypt_file(source, destination, self.key)

            return self._ok(
                message="Arquivo extraído com sucesso.",
                destination=destination,
            )
        except Exception as e:
            return self._error(
                "Não foi possível descriptografar o arquivo. "
                "Se ele veio de uma versão anterior e a senha já foi alterada, "
                f"verifique a chave usada originalmente. Detalhes: {e}"
            )

    def delete_file(self, vault_name):
        with self._lock:
            if not self._require_login():
                return self._error("O cofre está bloqueado.")

            item = self._find_item(vault_name)
            if not item:
                return self._error("Arquivo não encontrado.")

            path = self._vault_path(item.get("vault_name"))

            try:
                if os.path.exists(path):
                    os.remove(path)

                self.index = [
                    x for x in self.index
                    if x.get("vault_name") != item["vault_name"]
                ]
                save_index(self.key, self.index)

                return self._ok(
                    message="Arquivo excluído do cofre.",
                    stats=self._stats(),
                )
            except Exception as e:
                return self._error(f"Não foi possível excluir o arquivo: {e}")

    def get_file_details(self, vault_name):
        with self._lock:
            if not self._require_login():
                return self._error("O cofre está bloqueado.")

            item = self._find_item(vault_name)
            if not item:
                return self._error("Arquivo não encontrado.")

            size = int(item.get("size", 0) or 0)
            return self._ok(details={
                "name": item.get("name", "-"),
                "size": format_size(size),
                "size_bytes": size,
                "type": item.get("type", "-"),
                "date": item.get("date", "-"),
                "vault_name": item.get("vault_name", "-"),
            })

    def change_password(self, old_password, new_password, confirm):
        """
        Troca segura de senha:
        1. valida a senha atual;
        2. deriva a nova chave;
        3. recriptografa CADA .vault em memória para arquivos temporários
           (nenhum conteúdo em texto puro é gravado em disco);
        4. mantém backups (criptografados) dos arquivos antigos;
        5. troca os .vault, o índice e a configuração;
        6. em qualquer erro, restaura os backups.
        """
        with self._lock:
            if not self._require_login():
                return self._error("O cofre está bloqueado.")
            if not os.path.exists(DATA_FILE):
                return self._error("Ainda não existe um cofre.")

            old_password = str(old_password or "")
            new_password = str(new_password or "")
            confirm = str(confirm or "")

            old_key = unlock_key(old_password)
            if not old_key:
                return self._error("A senha atual está incorreta.")

            if len(new_password) < 8:
                return self._error("A nova senha deve ter pelo menos 8 caracteres.")

            if new_password != confirm:
                return self._error("As novas senhas não são iguais.")

            if old_password == new_password:
                return self._error("A nova senha deve ser diferente da senha atual.")

            transaction_dir = None
            new_dir = None
            backup_dir = None
            replaced = []
            old_data = None
            old_index = None

            try:
                items = load_index(old_key)
                items = self._recover_missing_entries(items)

                new_salt = secure_random(SALT_SIZE)
                new_key = derive_key(new_password, new_salt)
                new_verification = make_verification(new_key)

                os.makedirs(TEMP_DIR, exist_ok=True)
                transaction_dir = tempfile.mkdtemp(prefix="rekey_", dir=TEMP_DIR)
                new_dir = os.path.join(transaction_dir, "new")
                backup_dir = os.path.join(transaction_dir, "backup")
                os.makedirs(new_dir, exist_ok=True)
                os.makedirs(backup_dir, exist_ok=True)

                # Guarda configuração/índice atuais para rollback.
                if os.path.exists(DATA_FILE):
                    with open(DATA_FILE, "rb") as f:
                        old_data = f.read()
                if os.path.exists(INDEX_FILE):
                    with open(INDEX_FILE, "rb") as f:
                        old_index = f.read()

                # Prepara todos os novos .vault antes de substituir qualquer original.
                prepared = []
                for item in items:
                    filename = os.path.basename(str(item.get("vault_name") or ""))
                    if not filename:
                        continue

                    source = os.path.join(VAULT_DIR, filename)
                    if not os.path.exists(source):
                        continue

                    shutil.copy2(source, os.path.join(backup_dir, filename))

                    plain = decrypt_bytes(source, old_key)
                    atomic_write_bytes(
                        os.path.join(new_dir, filename),
                        encrypt_bytes(plain, new_key),
                    )
                    del plain

                    prepared.append(filename)

                # Só agora substitui os originais.
                for filename in prepared:
                    new_temp = os.path.join(new_dir, filename)
                    original = os.path.join(VAULT_DIR, filename)
                    os.replace(new_temp, original)
                    replaced.append(filename)

                # Atualiza índice e configuração somente após os arquivos.
                save_index(new_key, items)
                save_config(new_salt, new_verification)

                self.key = new_key
                self.password = new_password
                self.index = items

                shutil.rmtree(transaction_dir, ignore_errors=True)

                return self._ok(
                    message=(
                        "Senha alterada com sucesso. "
                        f"{len(replaced)} arquivo(s) foram recriptografados com a nova chave."
                    )
                )

            except Exception as e:
                # Restaura .vault antigos
                if backup_dir:
                    for filename in replaced:
                        backup = os.path.join(backup_dir, filename)
                        original = os.path.join(VAULT_DIR, filename)
                        try:
                            if os.path.exists(backup):
                                shutil.copy2(backup, original)
                        except Exception:
                            pass

                # Restaura configuração e índice
                try:
                    if old_data is not None:
                        atomic_write_bytes(DATA_FILE, old_data)
                except Exception:
                    pass

                try:
                    if old_index is not None:
                        atomic_write_bytes(INDEX_FILE, old_index)
                except Exception:
                    pass

                if transaction_dir:
                    shutil.rmtree(transaction_dir, ignore_errors=True)

                return self._error(
                    "A troca de senha foi cancelada e os arquivos anteriores foram "
                    f"restaurados. Detalhes: {e}"
                )

    def open_vault_folder(self):
        try:
            ensure_directories()
            if sys.platform.startswith("win"):
                os.startfile(VAULT_DIR)
            elif sys.platform == "darwin":
                subprocess.Popen(["open", VAULT_DIR])
            else:
                subprocess.Popen(["xdg-open", VAULT_DIR])
            return self._ok(message="Pasta do cofre aberta.")
        except Exception as e:
            return self._error(f"Não foi possível abrir a pasta: {e}", path=VAULT_DIR)

    def get_storage_location(self):
        return self._ok(path=VAULT_DIR)

    def _find_item(self, vault_name):
        for item in self.index:
            if item.get("vault_name") == vault_name:
                return item
        return None

    def _stats(self):
        total_size = 0
        for item in self.index:
            try:
                total_size += int(item.get("size", 0) or 0)
            except Exception:
                pass

        return {
            "files": len(self.index),
            "size": total_size,
            "size_text": format_size(total_size),
            "security": "AES-256 GCM",
        }

    def _recover_missing_entries(self, index):
        known = {x.get("vault_name") for x in index if x.get("vault_name")}

        try:
            files = os.listdir(VAULT_DIR)
        except Exception:
            return index

        for filename in files:
            if not filename.endswith(".vault") or filename in known:
                continue

            path = os.path.join(VAULT_DIR, filename)
            try:
                index.append({
                    "vault_name": filename,
                    "name": "Arquivo protegido (versão anterior)",
                    "size": os.path.getsize(path),
                    "date": "Anterior à V4",
                    "type": "Protegido",
                })
            except Exception:
                pass

        return index


# ============================================================
# HTML / CSS / JAVASCRIPT
# ============================================================

HTML = r"""
<!DOCTYPE html>
<html lang="pt-BR">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Cofre Digital V4.2.0</title>
<style>
:root{
  --bg:#050816;
  --bg2:#081125;
  --panel:rgba(12,22,45,.78);
  --panel-solid:#0d1830;
  --panel2:#111f3d;
  --line:rgba(130,170,255,.16);
  --line2:rgba(77,224,255,.32);
  --text:#f3f7ff;
  --muted:#8ea0c0;
  --cyan:#3ee8ff;
  --blue:#4f7cff;
  --violet:#8a5cff;
  --green:#2ee69c;
  --red:#ff6681;
  --yellow:#ffd166;
  --shadow:0 25px 80px rgba(0,0,0,.45);
  --radius:22px;
}
*{box-sizing:border-box}
html,body{margin:0;width:100%;height:100%;overflow:hidden}
body{
  font-family:Segoe UI,Inter,Arial,sans-serif;
  color:var(--text);
  background:
    radial-gradient(circle at 20% 15%,rgba(61,101,255,.18),transparent 35%),
    radial-gradient(circle at 80% 80%,rgba(102,48,255,.15),transparent 36%),
    linear-gradient(135deg,#040711,#071022 55%,#040712);
  user-select:none;
}
button,input{font:inherit}
button{cursor:pointer}
button:disabled{opacity:.35;cursor:default}
.hidden{display:none!important}
#spaceCanvas{
  position:fixed;inset:0;width:100%;height:100%;
  z-index:0;opacity:.72;pointer-events:none;
}
.bg-grid{
  position:fixed;inset:0;z-index:0;pointer-events:none;opacity:.17;
  background-image:
    linear-gradient(rgba(69,176,255,.12) 1px,transparent 1px),
    linear-gradient(90deg,rgba(69,176,255,.12) 1px,transparent 1px);
  background-size:70px 70px;
  mask-image:linear-gradient(to bottom,rgba(0,0,0,.8),transparent 85%);
}
.app-layer{position:relative;z-index:2;width:100%;height:100%}

/* LOGIN */
.login-screen{
  width:100%;height:100%;display:grid;
  grid-template-columns:minmax(420px,1.25fr) minmax(390px,.75fr);
  gap:30px;padding:34px;
}
.login-visual,.login-card{
  border:1px solid var(--line);
  background:linear-gradient(150deg,rgba(14,26,54,.78),rgba(5,12,28,.64));
  backdrop-filter:blur(18px);
  box-shadow:var(--shadow);
}
.login-visual{
  border-radius:32px;position:relative;overflow:hidden;
  display:flex;flex-direction:column;justify-content:space-between;padding:42px;
}
.brand{display:flex;align-items:center;gap:14px}
.brand-mark{
  width:46px;height:46px;border-radius:15px;display:grid;place-items:center;
  background:linear-gradient(135deg,var(--cyan),var(--blue),var(--violet));
  color:#06101d;font-size:23px;font-weight:900;
  box-shadow:0 0 35px rgba(62,232,255,.28);
}
.brand strong{font-size:20px;letter-spacing:.3px}
.brand small{display:block;color:var(--muted);margin-top:3px}
.hero-copy{max-width:620px;z-index:3}
.hero-copy h1{
  font-size:clamp(38px,5vw,74px);line-height:.98;margin:0 0 18px;
  letter-spacing:-2.6px;
}
.hero-copy h1 span{
  background:linear-gradient(90deg,var(--cyan),#8ca6ff,var(--violet));
  -webkit-background-clip:text;background-clip:text;color:transparent;
}
.hero-copy p{color:#aab8d1;font-size:16px;line-height:1.65;max-width:560px}
.hero-tags{display:flex;gap:9px;flex-wrap:wrap;margin-top:22px}
.tag{
  padding:9px 12px;border:1px solid var(--line2);border-radius:999px;
  background:rgba(17,39,72,.55);color:#bfefff;font-size:12px;
}
.login-card{
  border-radius:32px;padding:42px;display:flex;flex-direction:column;
  justify-content:center;max-width:560px;width:100%;justify-self:end;
}
.login-card .eyebrow{
  color:var(--cyan);font-size:12px;font-weight:800;letter-spacing:1.9px;
  text-transform:uppercase;margin-bottom:10px;
}
.login-card h2{font-size:32px;margin:0 0 8px}
.login-card .subtitle{color:var(--muted);line-height:1.55;margin:0 0 28px}
.field{margin:12px 0}
.field label{
  display:block;color:#c8d5ea;font-size:12px;font-weight:700;margin:0 0 8px;
}
.input-shell{
  display:flex;align-items:center;background:rgba(3,9,23,.78);
  border:1px solid rgba(125,160,220,.2);border-radius:14px;overflow:hidden;
  transition:.2s;
}
.input-shell:focus-within{
  border-color:var(--cyan);box-shadow:0 0 0 3px rgba(62,232,255,.08);
}
.input-shell span{width:46px;text-align:center;color:#7890b8}
.input-shell input{
  width:100%;border:0;outline:0;background:transparent;color:var(--text);
  padding:15px 10px 15px 0;
}
.input-shell select{
  width:100%;border:0;outline:0;background:#071126;color:var(--text);
  padding:15px 10px 15px 0;appearance:none;
}
.profile-hint{
  margin-top:12px;padding:11px 13px;border:1px solid rgba(62,232,255,.14);
  border-radius:12px;background:rgba(10,28,52,.42);color:#91a8c9;font-size:12px;
}
.profile-hint b{color:#ccefff}
.eye{
  width:46px;border:0;background:transparent;color:#8093b3;padding:0 10px;
}
.primary{
  width:100%;border:0;border-radius:14px;padding:15px 18px;margin-top:18px;
  font-weight:800;color:#06101f;
  background:linear-gradient(100deg,var(--cyan),#6c88ff 58%,#a26cff);
  box-shadow:0 12px 35px rgba(57,181,255,.2);
  transition:.2s;
}
.primary:hover{transform:translateY(-1px);filter:brightness(1.08)}
.secondary{
  width:100%;border:1px solid var(--line);border-radius:14px;padding:13px 18px;
  color:#c6d5ee;background:rgba(13,28,55,.55);margin-top:10px;
}
.login-footer{
  color:#6f82a4;font-size:11px;text-align:center;margin-top:24px;
}

/* 3D */
.vault-scene{
  position:absolute;right:4%;top:50%;width:min(38vw,530px);height:min(38vw,530px);
  transform:translateY(-48%);perspective:900px;pointer-events:none;
  opacity:.94;
}
.vault-orbit{
  position:absolute;inset:8%;border-radius:50%;
  border:1px solid rgba(75,229,255,.25);
  transform-style:preserve-3d;
  animation:orbitA 13s linear infinite;
}
.vault-orbit.o2{inset:18%;border-color:rgba(133,91,255,.36);animation:orbitB 9s linear infinite}
.vault-orbit.o3{inset:29%;border-color:rgba(75,121,255,.35);animation:orbitC 7s linear infinite}
.vault-cube{
  position:absolute;left:50%;top:50%;width:150px;height:150px;
  transform-style:preserve-3d;
  transform:translate(-50%,-50%) rotateX(-16deg) rotateY(28deg);
  animation:cubeFloat 5s ease-in-out infinite;
}
.face{
  position:absolute;width:150px;height:150px;border:1px solid rgba(110,221,255,.42);
  background:linear-gradient(145deg,rgba(14,43,78,.9),rgba(8,16,42,.82));
  box-shadow:inset 0 0 35px rgba(34,175,255,.08);
}
.front{transform:translateZ(75px);display:grid;place-items:center}
.back{transform:rotateY(180deg) translateZ(75px)}
.right{transform:rotateY(90deg) translateZ(75px)}
.left{transform:rotateY(-90deg) translateZ(75px)}
.top{transform:rotateX(90deg) translateZ(75px)}
.bottom{transform:rotateX(-90deg) translateZ(75px)}
.lock-disc{
  width:82px;height:82px;border-radius:50%;display:grid;place-items:center;
  border:4px double var(--cyan);font-size:34px;
  box-shadow:0 0 35px rgba(62,232,255,.4),inset 0 0 25px rgba(62,232,255,.12);
}
.vault-glow{
  position:absolute;left:50%;top:50%;width:280px;height:280px;
  transform:translate(-50%,-50%);border-radius:50%;
  background:radial-gradient(circle,rgba(68,210,255,.18),transparent 67%);
  filter:blur(10px);
}
@keyframes orbitA{to{transform:rotateX(70deg) rotateZ(360deg)}}
@keyframes orbitB{to{transform:rotateY(70deg) rotateZ(-360deg)}}
@keyframes orbitC{to{transform:rotateX(25deg) rotateY(360deg)}}
@keyframes cubeFloat{
  0%,100%{transform:translate(-50%,-50%) rotateX(-16deg) rotateY(28deg) translateY(0)}
  50%{transform:translate(-50%,-50%) rotateX(-10deg) rotateY(48deg) translateY(-12px)}
}

/* MAIN */
.main-screen{width:100%;height:100%;display:grid;grid-template-columns:260px 1fr}
.sidebar{
  border-right:1px solid var(--line);background:rgba(5,12,28,.86);
  backdrop-filter:blur(18px);padding:24px 18px;display:flex;flex-direction:column;
}
.sidebar .brand{padding:3px 8px 25px}
.nav{display:flex;flex-direction:column;gap:7px}
.nav-btn{
  border:0;background:transparent;color:#8fa2c4;border-radius:13px;
  text-align:left;padding:13px 14px;font-weight:650;display:flex;gap:12px;align-items:center;
}
.nav-btn:hover,.nav-btn.active{
  color:#eafbff;background:linear-gradient(90deg,rgba(57,218,255,.13),rgba(75,83,255,.09));
}
.nav-btn.active{border:1px solid rgba(76,220,255,.18)}
.side-spacer{flex:1}
.security-box{
  padding:15px;border:1px solid rgba(46,230,156,.18);border-radius:16px;
  background:rgba(18,52,52,.22);font-size:12px;color:#9ec8bd;
}
.security-dot{
  width:9px;height:9px;border-radius:50%;background:var(--green);
  box-shadow:0 0 13px var(--green);display:inline-block;margin-right:8px;
}
.content{
  min-width:0;height:100%;overflow:auto;padding:25px 28px 30px;
}
.topbar{
  display:flex;align-items:center;justify-content:space-between;gap:20px;margin-bottom:22px;
}
.topbar h1{font-size:28px;margin:0 0 4px}
.topbar p{margin:0;color:var(--muted);font-size:13px}
.actions{display:flex;gap:9px}
.icon-btn,.ghost-btn{
  border:1px solid var(--line);background:rgba(16,30,58,.62);
  color:#b9c7de;border-radius:12px;padding:10px 13px;
}
.ghost-btn:hover,.icon-btn:hover{border-color:rgba(70,223,255,.38);color:white}
.stats{
  display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:14px;margin-bottom:17px;
}
.stat{
  border:1px solid var(--line);border-radius:18px;padding:18px;
  background:linear-gradient(145deg,rgba(13,27,54,.74),rgba(7,17,37,.68));
  box-shadow:0 12px 40px rgba(0,0,0,.12);
}
.stat .label{font-size:11px;letter-spacing:1.25px;color:#8295b8;font-weight:800}
.stat .value{font-size:25px;font-weight:800;margin-top:7px}
.stat .hint{font-size:11px;color:#6f83a7;margin-top:5px}
.stat:nth-child(3) .value{color:#7ff7c2}
.workspace{
  border:1px solid var(--line);border-radius:22px;
  background:rgba(7,16,35,.74);overflow:hidden;box-shadow:var(--shadow);
}
.toolbar{
  padding:14px 15px;border-bottom:1px solid var(--line);
  display:flex;gap:9px;align-items:center;flex-wrap:wrap;
}
.add-btn{
  border:0;border-radius:12px;padding:11px 15px;font-weight:800;
  color:#06101f;background:linear-gradient(100deg,var(--cyan),#6d84ff);
}
.tool-btn{
  border:1px solid var(--line);border-radius:12px;padding:10px 13px;
  color:#b7c6df;background:rgba(15,30,58,.56);
}
.tool-btn:hover:not(:disabled){border-color:rgba(70,223,255,.38);color:white}
.tool-btn.danger:hover{border-color:rgba(255,102,129,.5);color:#ff9aae}
.search{
  margin-left:auto;min-width:260px;display:flex;align-items:center;
  border:1px solid var(--line);border-radius:12px;background:rgba(2,8,20,.55);
  padding:0 11px;
}
.search input{
  width:100%;background:transparent;border:0;outline:0;color:white;padding:11px 8px;
}
.table-wrap{overflow:auto;min-height:300px}
table{border-collapse:collapse;width:100%;min-width:760px}
th{
  text-align:left;font-size:11px;letter-spacing:.9px;color:#6f84a8;
  padding:13px 18px;border-bottom:1px solid var(--line);
}
td{
  padding:14px 18px;border-bottom:1px solid rgba(119,150,205,.08);
  color:#b9c9e1;font-size:13px;
}
tbody tr{transition:.14s;cursor:pointer}
tbody tr:hover{background:rgba(47,96,160,.08)}
tbody tr.selected{
  background:linear-gradient(90deg,rgba(60,213,255,.13),rgba(112,84,255,.08));
  outline:1px solid rgba(60,213,255,.16);
}
.file-cell{display:flex;align-items:center;gap:11px}
.file-icon{
  width:36px;height:36px;border-radius:10px;display:grid;place-items:center;flex-shrink:0;
  background:linear-gradient(145deg,rgba(54,211,255,.14),rgba(92,84,255,.13));
  border:1px solid rgba(91,187,255,.17);font-size:17px;
}
.file-name{color:#e9f2ff;font-weight:650}
.empty{
  padding:72px 20px;text-align:center;color:#7083a5;
}
.empty .big{font-size:42px;margin-bottom:12px}
.statusbar{
  display:flex;justify-content:space-between;gap:20px;padding:11px 16px;
  color:#63779a;font-size:11px;background:rgba(5,12,27,.72);
}
.status-secure{color:#76d7b4}

/* MODAL / TOAST */
.modal-backdrop{
  position:fixed;inset:0;background:rgba(0,4,13,.72);backdrop-filter:blur(9px);
  z-index:20;display:grid;place-items:center;padding:20px;
}
.modal{
  width:min(520px,100%);border:1px solid rgba(115,166,255,.2);
  border-radius:22px;background:#0b1730;box-shadow:var(--shadow);padding:24px;
}
.modal h3{font-size:22px;margin:0 0 7px}
.modal p{color:var(--muted);font-size:13px;line-height:1.55}
.modal-actions{display:flex;gap:9px;justify-content:flex-end;margin-top:18px}
.modal-actions button{width:auto;margin:0}
.danger-primary{
  border:0;border-radius:12px;padding:11px 15px;background:var(--red);color:white;font-weight:750;
}
#toastBox{
  position:fixed;right:22px;bottom:22px;z-index:40;display:flex;
  flex-direction:column;gap:9px;pointer-events:none;
}
.toast{
  min-width:300px;max-width:430px;padding:13px 15px;border:1px solid var(--line);
  border-radius:13px;background:rgba(10,23,46,.95);box-shadow:0 18px 45px rgba(0,0,0,.35);
  color:#c8d8ee;animation:toastIn .22s ease;
}
.toast.ok{border-color:rgba(46,230,156,.32)}
.toast.error{border-color:rgba(255,102,129,.4);color:#ffc0cb}
@keyframes toastIn{from{transform:translateY(10px);opacity:0}to{transform:none;opacity:1}}
.loading{
  position:fixed;inset:0;z-index:100;background:#050816;display:grid;place-items:center;
}
.loader{
  width:55px;height:55px;border-radius:50%;border:3px solid rgba(80,130,220,.15);
  border-top-color:var(--cyan);animation:spin .75s linear infinite;
}
@keyframes spin{to{transform:rotate(360deg)}}

/* VISUALIZADOR */
.viewer-backdrop{
  position:fixed;inset:0;z-index:25;background:rgba(0,4,13,.84);
  backdrop-filter:blur(10px);display:grid;place-items:center;padding:20px;
}
.viewer{
  width:min(1180px,100%);height:min(92vh,900px);display:flex;flex-direction:column;
  border:1px solid rgba(115,166,255,.22);border-radius:22px;background:#0b1730;
  box-shadow:var(--shadow);overflow:hidden;
}
.viewer-head{
  display:flex;align-items:center;justify-content:space-between;gap:14px;
  padding:14px 16px;border-bottom:1px solid var(--line);
}
.viewer-title{display:flex;align-items:center;gap:12px;min-width:0}
.viewer-title b{
  display:block;color:#eaf3ff;white-space:nowrap;overflow:hidden;
  text-overflow:ellipsis;max-width:42vw;
}
.viewer-title small{display:block;color:var(--muted);font-size:11px;margin-top:3px}
.viewer-tools{display:flex;gap:7px;align-items:center;flex-shrink:0}
.viewer-zoom{display:flex;gap:6px;align-items:center;margin-right:8px}
.viewer-zoom .zoom-label{
  min-width:56px;text-align:center;color:#9fb3d4;font-size:12px;
}
.viewer-body{
  flex:1;min-height:0;display:flex;background:rgba(2,7,18,.78);
}
.viewer-stage{
  flex:1;min-width:0;min-height:0;display:flex;overflow:auto;padding:16px;
}
.viewer-stage img{
  margin:auto;flex:none;max-width:100%;
  max-height:calc(min(92vh,900px) - 190px);
  border-radius:8px;box-shadow:0 14px 50px rgba(0,0,0,.5);
  background:repeating-conic-gradient(#14213f 0% 25%,#0e1a34 0% 50%) 50% / 20px 20px;
}
.viewer-stage img.zoomed{max-width:none;max-height:none}
.viewer-stage video{
  margin:auto;max-width:100%;max-height:100%;border-radius:10px;background:#000;
}
.viewer-frame{flex:1;border:0;width:100%;height:100%;background:#fff}
.viewer-text{
  margin:0;flex:1;min-width:0;overflow:auto;padding:18px 22px;
  font:13px/1.6 Consolas,"Courier New",monospace;color:#d6e4f7;
  white-space:pre-wrap;word-break:break-word;user-select:text;cursor:text;
}
.viewer-center{
  margin:auto;text-align:center;color:#8ea0c0;max-width:440px;padding:20px;
  line-height:1.55;font-size:14px;
}
.viewer-center .big{font-size:48px;margin-bottom:12px}
.viewer-center h4{margin:0 0 8px;font-size:18px;color:#e6f0ff}
.viewer-center audio{width:min(480px,80vw);margin-top:18px}
.viewer-foot{
  display:flex;justify-content:space-between;gap:16px;padding:10px 16px;
  border-top:1px solid var(--line);font-size:11px;color:#63779a;
  background:rgba(5,12,27,.72);
}

@media(max-width:980px){
  .login-screen{grid-template-columns:1fr;padding:20px}
  .login-visual{display:none}
  .login-card{justify-self:center;max-width:540px}
  .main-screen{grid-template-columns:82px 1fr}
  .sidebar{padding:18px 10px}
  .sidebar .brand strong,.sidebar .brand small,.nav-btn span.label,.security-box{display:none}
  .sidebar .brand{justify-content:center;padding-left:0;padding-right:0}
  .nav-btn{justify-content:center;font-size:18px}
  .stats{grid-template-columns:1fr}
}
@media(max-width:700px){
  .main-screen{display:block}
  .sidebar{display:none}
  .content{padding:18px 14px}
  .topbar{align-items:flex-start}
  .topbar h1{font-size:22px}
  .toolbar{align-items:stretch}
  .search{margin-left:0;min-width:100%;order:5}
  .tool-btn,.add-btn{flex:1}
  .viewer-backdrop{padding:8px}
  .viewer-title b{max-width:28vw}
  .viewer-tools .tool-btn{padding:8px 10px;flex:none}
  .viewer-foot{flex-direction:column;gap:4px}
}
</style>
</head>
<body>
<canvas id="spaceCanvas"></canvas>
<div class="bg-grid"></div>
<div id="app" class="app-layer"></div>
<div id="toastBox"></div>


<script>
const app = document.getElementById('app');
const toastBox = document.getElementById('toastBox');

const BOOT_STATE = __BOOT_STATE__;
let state = {...BOOT_STATE, logged_in:false};
let bridgeReady = false;
let files = [];
let selectedVault = null;
let currentFilter = '';
let currentPage = 'dashboard';
let passwordBusy = false;

function esc(s){
  return String(s ?? '').replace(/[&<>"']/g, c => ({
    '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#039;'
  }[c]));
}

function toast(message, type='ok'){
  const el = document.createElement('div');
  el.className = 'toast ' + type;
  el.textContent = message;
  toastBox.appendChild(el);
  setTimeout(()=>{ el.style.opacity='0'; el.style.transform='translateY(8px)'; }, 3500);
  setTimeout(()=>el.remove(), 3900);
}

function fileEmoji(type){
  type = String(type||'').toUpperCase();
  if(['PNG','JPG','JPEG','GIF','WEBP','BMP','SVG'].includes(type)) return '🖼️';
  if(['MP4','MKV','AVI','MOV','WEBM'].includes(type)) return '🎬';
  if(['MP3','WAV','FLAC','AAC','OGG','M4A'].includes(type)) return '🎵';
  if(['ZIP','RAR','7Z','TAR','GZ'].includes(type)) return '📦';
  if(['PDF'].includes(type)) return '📕';
  if(['DOC','DOCX','TXT','RTF','MD'].includes(type)) return '📄';
  if(['XLS','XLSX','CSV'].includes(type)) return '📊';
  return '🔐';
}

function sleep(ms){ return new Promise(resolve => setTimeout(resolve, ms)); }

let bridgePromise = null;

function bridgeAvailable(){
  return !!(window.pywebview && window.pywebview.api);
}

function getBridgePromise(){
  if(bridgeAvailable()){
    bridgeReady = true;
    return Promise.resolve(true);
  }

  if(!bridgePromise){
    bridgePromise = new Promise(resolve => {
      let pollTimer = null;

      const finishIfReady = () => {
        if(!bridgeAvailable()) return;
        bridgeReady = true;
        if(pollTimer) clearInterval(pollTimer);
        window.removeEventListener('pywebviewready', onReady);
        resolve(true);
      };

      const onReady = () => {
        // Em algumas inicializações a API aparece alguns milissegundos
        // depois do evento. O polling abaixo cobre os dois casos.
        setTimeout(finishIfReady, 0);
      };

      window.addEventListener('pywebviewready', onReady);
      pollTimer = setInterval(finishIfReady, 100);
      finishIfReady();
    });
  }

  return bridgePromise;
}

async function waitForBridge(timeout=0){
  const readyPromise = getBridgePromise();
  if(!timeout) return await readyPromise;

  return await Promise.race([
    readyPromise,
    sleep(timeout).then(() => false)
  ]);
}

async function api(name, ...args){
  try{
    // Só há limite quando o usuário executa uma ação. A abertura do programa
    // nunca mostra erro apenas porque o WebView2 iniciou mais devagar.
    const ready = await waitForBridge(60000);
    const fn = window.pywebview?.api?.[name];

    if(!ready || typeof fn !== 'function'){
      throw new Error(
        'Não foi possível iniciar a comunicação interna do Cofre. ' +
        'Feche o programa e abra novamente.'
      );
    }

    return await fn(...args);
  }catch(e){
    const message = String(e?.message || e);
    toast('Erro: ' + message, 'error');
    return {ok:false, message};
  }
}

function renderLogin(mode='login'){
  closeViewer();
  selectedVault = null;
  const profiles = Array.isArray(state.profiles) ? state.profiles : [];
  const hasProfiles = profiles.length > 0;
  const createMode = mode === 'create' || !hasProfiles;

  app.innerHTML = `
    <section class="login-screen">
      <div class="login-visual">
        <div class="brand">
          <div class="brand-mark">◆</div>
          <div><strong>Cofre Digital</strong><small>Security 3D · V${esc(state.version)}</small></div>
        </div>

        <div class="vault-scene" id="vaultScene">
          <div class="vault-glow"></div>
          <div class="vault-orbit"></div>
          <div class="vault-orbit o2"></div>
          <div class="vault-orbit o3"></div>
          <div class="vault-cube">
            <div class="face front"><div class="lock-disc">🔐</div></div>
            <div class="face back"></div>
            <div class="face right"></div>
            <div class="face left"></div>
            <div class="face top"></div>
            <div class="face bottom"></div>
          </div>
        </div>

        <div class="hero-copy">
          <h1>Seus arquivos.<br><span>Sua fortaleza.</span></h1>
          <p>Agora cada cadastro possui seu próprio cofre, senha, índice e arquivos criptografados. Um perfil não acessa o conteúdo do outro.</p>
          <div class="hero-tags">
            <span class="tag">AES-256 GCM</span>
            <span class="tag">Múltiplos cadastros</span>
            <span class="tag">100% local</span>
            <span class="tag">Visualizador integrado</span>
          </div>
        </div>
      </div>

      <div class="login-card">
        <div class="eyebrow">${createMode ? (hasProfiles ? 'Novo cadastro' : 'Primeiro acesso') : 'Acesso protegido'}</div>
        <h2>${createMode ? 'Criar cadastro' : 'Bem-vindo de volta'}</h2>
        <p class="subtitle">${createMode
          ? 'Crie um perfil independente. Cada cadastro terá sua própria senha e seus próprios arquivos protegidos.'
          : 'Selecione seu cadastro e digite a senha para abrir somente o seu cofre.'}</p>

        ${createMode ? `
        <div class="field">
          <label>NOME DO CADASTRO</label>
          <div class="input-shell">
            <span>👤</span>
            <input id="username" type="text" maxlength="40" autocomplete="off" placeholder="Ex.: Gustavo">
          </div>
        </div>` : `
        <div class="field">
          <label>CADASTRO</label>
          <div class="input-shell">
            <span>👤</span>
            <select id="profileSelect">
              ${profiles.map(p=>`<option value="${esc(p.id)}">${esc(p.username)}</option>`).join('')}
            </select>
          </div>
        </div>`}

        <div class="field">
          <label>${createMode ? 'SENHA DO CADASTRO' : 'SENHA'}</label>
          <div class="input-shell">
            <span>🔑</span>
            <input id="password" type="password" autocomplete="off" placeholder="Digite sua senha">
            <button class="eye" onclick="togglePass('password')">◉</button>
          </div>
        </div>

        ${createMode ? `
        <div class="field">
          <label>CONFIRMAR SENHA</label>
          <div class="input-shell">
            <span>✓</span>
            <input id="confirm" type="password" autocomplete="off" placeholder="Digite novamente">
            <button class="eye" onclick="togglePass('confirm')">◉</button>
          </div>
        </div>` : ''}

        <button class="primary" onclick="${createMode ? 'createProfile()' : 'doLogin()'}">
          ${createMode ? '＋ Criar cadastro e cofre' : '🔓 Entrar no meu cofre'}
        </button>

        ${hasProfiles ? `
          <button class="secondary" onclick="renderLogin('${createMode ? 'login' : 'create'}')">
            ${createMode ? '← Voltar para entrar' : '＋ Novo cadastro'}
          </button>
        ` : ''}

        <div class="profile-hint">
          ${hasProfiles
            ? `<b>${profiles.length} cadastro(s)</b> neste computador. Cada um possui dados separados.`
            : 'O primeiro cadastro será criado sem alterar a segurança da criptografia.'}
        </div>

        <div class="login-footer">
          Cofre Digital V${esc(state.version)} · Dados armazenados localmente
        </div>
      </div>
    </section>
  `;

  setTimeout(()=>{
    const u = document.getElementById('username');
    const p = document.getElementById('password');
    if(u) u.focus(); else if(p) p.focus();
    if(u) u.addEventListener('keydown', e=>{ if(e.key==='Enter') p?.focus(); });
    if(p) p.addEventListener('keydown', e=>{ if(e.key==='Enter') createMode ? document.getElementById('confirm')?.focus() : doLogin(); });
    const c = document.getElementById('confirm');
    if(c) c.addEventListener('keydown', e=>{ if(e.key==='Enter') createProfile(); });

    const scene = document.getElementById('vaultScene');
    if(scene){
      document.removeEventListener('mousemove', loginParallax);
      document.addEventListener('mousemove', loginParallax, {passive:true});
    }
  }, 20);
}

function loginParallax(e){
  const scene = document.getElementById('vaultScene');
  if(!scene) return;
  const x = (e.clientX/window.innerWidth - .5) * 15;
  const y = (e.clientY/window.innerHeight - .5) * 12;
  scene.style.transform = `translateY(-48%) translate(${x}px,${y}px)`;
}

function togglePass(id){
  const el = document.getElementById(id);
  if(el) el.type = el.type === 'password' ? 'text' : 'password';
}

async function createProfile(){
  const username = document.getElementById('username')?.value || '';
  const p = document.getElementById('password')?.value || '';
  const c = document.getElementById('confirm')?.value || '';
  const r = await api('create_profile', username, p, c);
  if(!r.ok) return toast(r.message, 'error');
  state.profiles = r.profiles || state.profiles || [];
  state.configured = state.profiles.length > 0;
  state.current_user = r.current_user || null;
  state.logged_in = true;
  toast(r.message);
  await loadMain();
}

async function doLogin(){
  const profileId = document.getElementById('profileSelect')?.value || '';
  const p = document.getElementById('password')?.value || '';
  const r = await api('login', profileId, p);
  if(!r.ok){
    toast(r.message, 'error');
    const pass = document.getElementById('password');
    if(pass){ pass.value=''; pass.focus(); }
    return;
  }
  state.current_user = r.current_user || null;
  state.logged_in = true;
  toast(r.message);
  await loadMain();
}

async function loadMain(){
  const r = await api('list_files');
  if(!r.ok){
    toast(r.message, 'error');
    return renderLogin();
  }
  files = r.items || [];
  currentFilter = '';
  renderMain(r.stats);
}

function renderMain(stats){
  document.removeEventListener('mousemove', loginParallax);
  app.innerHTML = `
    <section class="main-screen">
      <aside class="sidebar">
        <div class="brand">
          <div class="brand-mark">◆</div>
          <div><strong>Cofre Digital</strong><small>Security 3D</small></div>
        </div>

        <nav class="nav">
          <button id="navDashboard" class="nav-btn active" onclick="showDashboard()">
            <b>⌂</b><span class="label">Painel principal</span>
          </button>
          <button id="navFiles" class="nav-btn" onclick="showFilesPage()">
            <b>▣</b><span class="label">Arquivos protegidos</span>
          </button>
          <button class="nav-btn" onclick="openSettings()">
            <b>⚙</b><span class="label">Segurança</span>
          </button>
        </nav>

        <div class="side-spacer"></div>
        <div class="security-box">
          <span class="security-dot"></span><b>Cofre desbloqueado</b><br><br>
          👤 ${esc(state.current_user?.username || 'Cadastro')}<br><br>
          Criptografia AES-256 GCM ativa nesta sessão.
        </div>
      </aside>

      <main class="content">
        <header class="topbar">
          <div>
            <h1 id="pageTitle">Painel do Cofre</h1>
            <p id="pageSubtitle">Cadastro: <b>${esc(state.current_user?.username || 'Cadastro')}</b> · Gerencie seus arquivos criptografados com segurança.</p>
          </div>
          <div class="actions">
            <button class="ghost-btn" onclick="openSettings()">⚙ Configurações</button>
            <button class="ghost-btn" onclick="lockVault()">🔒 Bloquear</button>
          </div>
        </header>

        <section class="stats" id="dashboardStats">
          <div class="stat">
            <div class="label">ARQUIVOS PROTEGIDOS</div>
            <div class="value" id="statFiles">${esc(stats?.files ?? files.length)}</div>
            <div class="hint">Itens armazenados no cofre</div>
          </div>
          <div class="stat">
            <div class="label">ESPAÇO OCUPADO</div>
            <div class="value" id="statSize">${esc(stats?.size_text ?? '0 B')}</div>
            <div class="hint">Tamanho original dos arquivos</div>
          </div>
          <div class="stat">
            <div class="label">SEGURANÇA</div>
            <div class="value">AES-256 GCM</div>
            <div class="hint">Criptografia autenticada ativa</div>
          </div>
        </section>

        <section class="workspace" id="filesWorkspace">
          <div class="toolbar">
            <button class="add-btn" onclick="addFiles()">＋ Adicionar</button>
            <button class="tool-btn" onclick="previewSelected()">👁 Visualizar</button>
            <button class="tool-btn" onclick="extractSelected()">⇩ Extrair</button>
            <button class="tool-btn" onclick="showDetails()">ⓘ Detalhes</button>
            <button class="tool-btn danger" onclick="deleteSelected()">🗑 Excluir</button>

            <div class="search">
              <span>⌕</span>
              <input id="searchBox" placeholder="Pesquisar arquivos..." oninput="filterFiles(this.value)">
            </div>
          </div>

          <div class="table-wrap">
            <table>
              <thead><tr>
                <th>ARQUIVO</th><th>TAMANHO</th><th>ADICIONADO EM</th><th>TIPO</th>
              </tr></thead>
              <tbody id="fileRows"></tbody>
            </table>
            <div id="emptyState" class="empty hidden">
              <div class="big">🔐</div>
              <div>Nenhum arquivo encontrado.</div>
            </div>
          </div>

          <div class="statusbar">
            <span id="statusCount">${files.length} arquivo(s)</span>
            <span class="status-secure">● Cofre criptografado localmente · duplo clique para visualizar</span>
          </div>
        </section>
      </main>
    </section>
  `;
  drawRows();
  showDashboard();
}

function setActiveNav(page){
  currentPage = page;

  const dashboard = document.getElementById('navDashboard');
  const filesNav = document.getElementById('navFiles');

  if(dashboard) dashboard.classList.toggle('active', page === 'dashboard');
  if(filesNav) filesNav.classList.toggle('active', page === 'files');
}

function showDashboard(){
  setActiveNav('dashboard');

  const stats = document.getElementById('dashboardStats');
  const title = document.getElementById('pageTitle');
  const subtitle = document.getElementById('pageSubtitle');
  const workspace = document.getElementById('filesWorkspace');

  if(stats) stats.style.display = 'grid';
  if(title) title.textContent = 'Painel do Cofre';

  if(subtitle){
    subtitle.innerHTML =
      `Cadastro: <b>${esc(state.current_user?.username || 'Cadastro')}</b> · ` +
      `Visão geral do seu cofre criptografado.`;
  }

  if(workspace){
    workspace.style.marginTop = '';
  }
}

function showFilesPage(){
  setActiveNav('files');

  const stats = document.getElementById('dashboardStats');
  const title = document.getElementById('pageTitle');
  const subtitle = document.getElementById('pageSubtitle');
  const workspace = document.getElementById('filesWorkspace');

  // Nesta página mostramos somente o gerenciador de arquivos.
  if(stats) stats.style.display = 'none';
  if(title) title.textContent = 'Arquivos protegidos';

  if(subtitle){
    subtitle.innerHTML =
      `Cadastro: <b>${esc(state.current_user?.username || 'Cadastro')}</b> · ` +
      `Adicione, visualize, pesquise, extraia ou exclua arquivos deste cofre.`;
  }

  if(workspace){
    workspace.style.marginTop = '4px';
  }

  const search = document.getElementById('searchBox');
  if(search) setTimeout(()=>search.focus(), 80);
}

function visibleFiles(){
  return files.filter(f => !currentFilter || String(f.name||'').toLowerCase().includes(currentFilter));
}

function filterFiles(q){
  currentFilter = String(q||'').trim().toLowerCase();
  selectedVault = null;
  drawRows();
}

function selectRow(id){
  selectedVault = id;
  const tbody = document.getElementById('fileRows');
  if(!tbody) return;
  tbody.querySelectorAll('tr').forEach(tr=>{
    tr.classList.toggle('selected', tr.dataset.id === id);
  });
}

function drawRows(){
  const tbody = document.getElementById('fileRows');
  const empty = document.getElementById('emptyState');
  if(!tbody) return;

  tbody.innerHTML = '';
  const visible = visibleFiles();

  if(empty) empty.classList.toggle('hidden', visible.length !== 0);

  visible.forEach(f=>{
    const tr = document.createElement('tr');
    if(f.vault_name === selectedVault) tr.classList.add('selected');
    tr.dataset.id = f.vault_name;

    const tdName = document.createElement('td');
    const cell = document.createElement('div');
    cell.className='file-cell';
    const icon = document.createElement('div');
    icon.className='file-icon';
    icon.textContent=fileEmoji(f.type);
    const name = document.createElement('div');
    name.className='file-name';
    name.textContent=f.name;
    cell.append(icon,name);
    tdName.appendChild(cell);

    const tdSize=document.createElement('td'); tdSize.textContent=f.size_text;
    const tdDate=document.createElement('td'); tdDate.textContent=f.date;
    const tdType=document.createElement('td'); tdType.textContent=f.type;

    tr.append(tdName,tdSize,tdDate,tdType);
    // A seleção apenas troca a classe; a tabela não é recriada, então o
    // duplo clique funciona corretamente.
    tr.addEventListener('click',()=>selectRow(f.vault_name));
    tr.addEventListener('dblclick',()=>{ selectRow(f.vault_name); openViewer(f.vault_name); });
    tbody.appendChild(tr);
  });

  const sc = document.getElementById('statusCount');
  if(sc) sc.textContent = `${visible.length} de ${files.length} arquivo(s)`;
}

async function refreshFiles(){
  const r = await api('list_files');
  if(!r.ok) return toast(r.message,'error');

  files = r.items || [];
  selectedVault = null;

  updateStats(r.stats);
  drawRows();

  // Preserva a aba selecionada depois de adicionar/excluir arquivos.
  if(currentPage === 'files') showFilesPage();
  else showDashboard();
}

function updateStats(stats){
  const a=document.getElementById('statFiles');
  const b=document.getElementById('statSize');
  if(a) a.textContent=stats?.files ?? files.length;
  if(b) b.textContent=stats?.size_text ?? '0 B';
}

async function addFiles(){
  toast('Selecione um ou mais arquivos para proteger.');
  const r = await api('add_files');
  if(!r.ok) return toast(r.message,'error');
  if(!r.cancelled) toast(r.message);
  await refreshFiles();
}

function needSelection(){
  if(!selectedVault){ toast('Selecione um arquivo primeiro.','error'); return false; }
  return true;
}

async function extractSelected(){
  if(!needSelection()) return;
  const r = await api('extract_file', selectedVault);
  if(!r.ok) return toast(r.message,'error');
  if(!r.cancelled) toast(r.message);
}

async function deleteSelected(){
  if(!needSelection()) return;
  const f = files.find(x=>x.vault_name===selectedVault);
  showConfirm(
    'Excluir arquivo',
    `Deseja excluir definitivamente "${f?.name || 'este arquivo'}"? Esta ação não poderá ser desfeita.`,
    async ()=>{
      const r=await api('delete_file',selectedVault);
      closeModal();
      if(!r.ok) return toast(r.message,'error');
      toast(r.message);
      await refreshFiles();
    }
  );
}

async function showDetails(){
  if(!needSelection()) return;
  const r = await api('get_file_details',selectedVault);
  if(!r.ok) return toast(r.message,'error');
  const d=r.details;
  showModal(`
    <h3>Detalhes do arquivo</h3>
    <p>
      <b>Nome:</b> ${esc(d.name)}<br><br>
      <b>Tamanho:</b> ${esc(d.size)}<br><br>
      <b>Tipo:</b> ${esc(d.type)}<br><br>
      <b>Adicionado em:</b> ${esc(d.date)}<br><br>
      <b>Arquivo interno:</b><br><span style="word-break:break-all;color:#7f96bc">${esc(d.vault_name)}</span>
    </p>
    <div class="modal-actions"><button class="secondary" onclick="closeModal()">Fechar</button></div>
  `);
}

/* ============================================================
   VISUALIZADOR DE ARQUIVOS
   ============================================================ */

const viewer = {open:false, id:null, token:0, urls:[], zoom:0};

function previewSelected(){
  if(!needSelection()) return;
  openViewer(selectedVault);
}

function stopViewerMedia(root){
  if(!root) return;
  root.querySelectorAll('video,audio').forEach(m=>{
    try{ m.pause(); m.removeAttribute('src'); m.load(); }catch(e){}
  });
}

function releaseViewerUrls(){
  viewer.urls.forEach(u=>{ try{ URL.revokeObjectURL(u); }catch(e){} });
  viewer.urls = [];
}

function b64ToBlobUrl(b64, mime){
  const bin = atob(b64);
  const bytes = new Uint8Array(bin.length);
  for(let i=0;i<bin.length;i++) bytes[i] = bin.charCodeAt(i);
  const url = URL.createObjectURL(new Blob([bytes], {type:mime}));
  viewer.urls.push(url);
  return url;
}

function openViewer(id){
  if(!id) return;
  closeViewer();

  const back = document.createElement('div');
  back.className = 'viewer-backdrop';
  back.id = 'viewerBackdrop';
  back.innerHTML = `
    <div class="viewer" role="dialog" aria-modal="true">
      <div class="viewer-head">
        <div class="viewer-title">
          <div class="file-icon" id="vIcon">🔐</div>
          <div style="min-width:0">
            <b id="vName"></b>
            <small id="vMeta"></small>
          </div>
        </div>
        <div class="viewer-tools">
          <div class="viewer-zoom hidden" id="vZoom">
            <button class="tool-btn" title="Diminuir" onclick="zoomImage('out')">−</button>
            <span class="zoom-label" id="vZoomLabel">Ajustar</span>
            <button class="tool-btn" title="Aumentar" onclick="zoomImage('in')">+</button>
            <button class="tool-btn" title="Ajustar à janela" onclick="zoomImage('fit')">Ajustar</button>
            <button class="tool-btn" title="Tamanho real" onclick="zoomImage('actual')">100%</button>
          </div>
          <button class="tool-btn" id="vPrev" title="Anterior (←)" onclick="viewerStep(-1)">‹</button>
          <button class="tool-btn" id="vNext" title="Próximo (→)" onclick="viewerStep(1)">›</button>
          <button class="tool-btn" onclick="viewerExtract()">⇩ Extrair</button>
          <button class="tool-btn" title="Fechar (Esc)" onclick="closeViewer()">✕</button>
        </div>
      </div>
      <div class="viewer-body" id="vBody"></div>
      <div class="viewer-foot">
        <span id="vInfo">🔒 Descriptografado apenas em memória — nada é gravado em disco.</span>
        <span id="vCount"></span>
      </div>
    </div>
  `;
  back.addEventListener('mousedown', e=>{ if(e.target === back) closeViewer(); });
  document.body.appendChild(back);
  viewer.open = true;
  loadViewerFile(id);
}

function closeViewer(){
  const v = document.getElementById('viewerBackdrop');
  viewer.open = false;
  viewer.token++;
  viewer.id = null;
  if(v){
    stopViewerMedia(v);
    v.remove();
  }
  releaseViewerUrls();
}

function viewerMessage(body, icon, title, text){
  stopViewerMedia(body);
  body.innerHTML = '';
  const box = document.createElement('div');
  box.className = 'viewer-center';
  const big = document.createElement('div'); big.className = 'big'; big.textContent = icon;
  const h = document.createElement('h4'); h.textContent = title;
  const p = document.createElement('div'); p.textContent = text;
  box.append(big, h, p);
  body.appendChild(box);
  return box;
}

function updateViewerHeader(f){
  const list = visibleFiles();
  const idx = list.findIndex(x => x.vault_name === viewer.id);

  const name = document.getElementById('vName');
  const meta = document.getElementById('vMeta');
  const icon = document.getElementById('vIcon');
  const count = document.getElementById('vCount');
  const prev = document.getElementById('vPrev');
  const next = document.getElementById('vNext');

  if(name) name.textContent = f?.name || 'Arquivo';
  if(meta) meta.textContent = [f?.type, f?.size_text, f?.date].filter(Boolean).join(' · ');
  if(icon) icon.textContent = fileEmoji(f?.type);
  if(count) count.textContent = idx >= 0 ? `${idx+1} / ${list.length}  ·  ← → navegar  ·  Esc fechar` : 'Esc para fechar';
  if(prev) prev.disabled = idx <= 0;
  if(next) next.disabled = idx < 0 || idx >= list.length - 1;
}

async function loadViewerFile(id){
  const token = ++viewer.token;
  viewer.id = id;
  viewer.zoom = 0;

  const body = document.getElementById('vBody');
  if(!body) return;

  stopViewerMedia(body);
  releaseViewerUrls();

  const f = files.find(x => x.vault_name === id);
  selectRow(id);
  document.querySelector('#fileRows tr.selected')?.scrollIntoView({block:'nearest'});
  updateViewerHeader(f);

  const zoomBox = document.getElementById('vZoom');
  if(zoomBox) zoomBox.classList.add('hidden');
  const info = document.getElementById('vInfo');
  if(info) info.textContent = '🔒 Descriptografado apenas em memória — nada é gravado em disco.';

  body.innerHTML = '<div class="viewer-center"><div class="loader" style="margin:0 auto 16px"></div><div>Descriptografando em memória...</div></div>';

  const r = await api('preview_file', id);
  if(token !== viewer.token || !viewer.open) return;

  try{
    renderPreview(body, r);
  }catch(e){
    viewerMessage(body, '⚠️', 'Não foi possível exibir o arquivo', String(e?.message || e));
  }
}

function renderPreview(body, r){
  const info = document.getElementById('vInfo');
  const zoomBox = document.getElementById('vZoom');

  if(!r.ok){
    return viewerMessage(body, '⚠️', 'Não foi possível abrir', r.message || 'Erro desconhecido.');
  }

  if(r.kind === 'too_large'){
    return viewerMessage(body, '📦', 'Arquivo grande demais para visualizar',
      `O limite do visualizador é ${r.limit_text}. Use o botão Extrair para salvar e abrir o arquivo.`);
  }

  if(r.kind === 'unsupported'){
    const ext = r.ext ? '.' + r.ext : 'sem extensão';
    return viewerMessage(body, '🔐', 'Visualização não disponível',
      `Este tipo de arquivo (${ext}) não pode ser exibido dentro do cofre. Use o botão Extrair para salvá-lo.`);
  }

  body.innerHTML = '';

  if(r.kind === 'image'){
    const url = b64ToBlobUrl(r.data, r.mime);
    const stage = document.createElement('div');
    stage.className = 'viewer-stage';
    const img = document.createElement('img');
    img.id = 'vImg';
    img.alt = r.name || '';
    img.draggable = false;
    img.onload = ()=>{
      if(info && img.naturalWidth) info.textContent = `🔒 Somente em memória · ${img.naturalWidth} × ${img.naturalHeight} px`;
      updateZoomLabel();
    };
    img.onerror = ()=>viewerMessage(body, '🖼️', 'Imagem não pôde ser exibida',
      'O arquivo pode estar danificado ou usar um formato não compatível. Use Extrair para salvá-lo.');
    img.src = url;
    stage.appendChild(img);
    body.appendChild(stage);
    if(zoomBox) zoomBox.classList.remove('hidden');
    updateZoomLabel();
    return;
  }

  if(r.kind === 'pdf'){
    const url = b64ToBlobUrl(r.data, 'application/pdf');
    const frame = document.createElement('iframe');
    frame.className = 'viewer-frame';
    frame.title = r.name || 'PDF';
    frame.src = url;
    body.appendChild(frame);
    if(info) info.textContent = '🔒 Somente em memória · se o PDF não aparecer, use Extrair';
    return;
  }

  if(r.kind === 'video'){
    const url = b64ToBlobUrl(r.data, r.mime);
    const stage = document.createElement('div');
    stage.className = 'viewer-stage';
    const video = document.createElement('video');
    video.controls = true;
    video.autoplay = false;
    video.onerror = ()=>viewerMessage(body, '🎬', 'Vídeo não pôde ser reproduzido',
      'O codec pode não ser compatível. Use Extrair para abrir em outro player.');
    video.src = url;
    stage.appendChild(video);
    body.appendChild(stage);
    return;
  }

  if(r.kind === 'audio'){
    const url = b64ToBlobUrl(r.data, r.mime);
    const box = viewerMessage(body, '🎵', r.name || 'Áudio', 'Reprodução em memória.');
    const audio = document.createElement('audio');
    audio.controls = true;
    audio.onerror = ()=>viewerMessage(body, '🎵', 'Áudio não pôde ser reproduzido',
      'O formato pode não ser compatível. Use Extrair para abrir em outro player.');
    audio.src = url;
    box.appendChild(audio);
    return;
  }

  if(r.kind === 'text'){
    const pre = document.createElement('pre');
    pre.className = 'viewer-text';
    pre.textContent = r.text && r.text.length ? r.text : '(arquivo vazio)';
    body.appendChild(pre);
    if(info){
      info.textContent = r.truncated
        ? `🔒 Somente em memória · exibindo os primeiros ${Number(r.chars).toLocaleString('pt-BR')} caracteres (arquivo truncado)`
        : `🔒 Somente em memória · ${Number(r.chars).toLocaleString('pt-BR')} caracteres`;
    }
    return;
  }

  viewerMessage(body, '🔐', 'Visualização não disponível', 'Tipo de conteúdo desconhecido.');
}

function updateZoomLabel(){
  const label = document.getElementById('vZoomLabel');
  if(!label) return;
  label.textContent = viewer.zoom ? Math.round(viewer.zoom * 100) + '%' : 'Ajustar';
}

function applyZoom(){
  const img = document.getElementById('vImg');
  if(!img) return;
  if(!viewer.zoom){
    img.classList.remove('zoomed');
    img.style.width = '';
    img.style.height = '';
  }else{
    img.classList.add('zoomed');
    img.style.width = Math.round(img.naturalWidth * viewer.zoom) + 'px';
    img.style.height = 'auto';
  }
  updateZoomLabel();
}

function zoomImage(mode){
  const img = document.getElementById('vImg');
  if(!img || !img.naturalWidth) return;

  if(mode === 'fit'){
    viewer.zoom = 0;
  }else if(mode === 'actual'){
    viewer.zoom = 1;
  }else{
    const base = viewer.zoom || (img.clientWidth / img.naturalWidth) || 1;
    viewer.zoom = Math.min(8, Math.max(0.05, base * (mode === 'in' ? 1.25 : 0.8)));
  }
  applyZoom();
}

function viewerStep(dir){
  if(!viewer.open) return;
  const list = visibleFiles();
  const idx = list.findIndex(x => x.vault_name === viewer.id);
  if(idx < 0) return;
  const target = list[idx + dir];
  if(target) loadViewerFile(target.vault_name);
}

async function viewerExtract(){
  if(!viewer.id) return;
  const r = await api('extract_file', viewer.id);
  if(!r.ok) return toast(r.message, 'error');
  if(!r.cancelled) toast(r.message);
}

document.addEventListener('keydown', e=>{
  if(!viewer.open) return;

  if(e.key === 'Escape'){
    closeViewer();
    return;
  }

  const tag = (e.target && e.target.tagName) || '';
  if(['VIDEO','AUDIO','INPUT','TEXTAREA','SELECT'].includes(tag)) return;

  if(e.key === 'ArrowLeft'){ e.preventDefault(); viewerStep(-1); }
  else if(e.key === 'ArrowRight'){ e.preventDefault(); viewerStep(1); }
});

/* ============================================================ */

function openSettings(){
  showModal(`
    <h3>⚙ Segurança e configurações</h3>
    <p>Cadastro ativo: <b>${esc(state.current_user?.username || 'Cadastro')}</b><br>Versão ${esc(state.version)} · AES-256 GCM · PBKDF2-SHA256</p>

    <button class="secondary" onclick="storageLocation()">📁 Onde ficam os arquivos?</button>
    <button class="secondary" onclick="openFolder()">📂 Abrir pasta do cofre</button>
    <button class="secondary" onclick="passwordModal()">🔑 Alterar senha</button>

    <div class="modal-actions"><button class="secondary" onclick="closeModal()">Fechar</button></div>
  `);
}

async function storageLocation(){
  const r=await api('get_storage_location');
  if(!r.ok) return toast(r.message,'error');
  showModal(`
    <h3>Local do cofre</h3>
    <p>Os arquivos criptografados ficam nesta pasta:</p>
    <p style="word-break:break-all;color:#bfefff">${esc(r.path)}</p>
    <p>Não renomeie ou altere manualmente os arquivos <b>.vault</b>.</p>
    <div class="modal-actions"><button class="secondary" onclick="openSettings()">Voltar</button></div>
  `);
}

async function openFolder(){
  const r=await api('open_vault_folder');
  if(!r.ok) toast(r.message,'error'); else toast(r.message);
}

function passwordModal(){
  showModal(`
    <h3>🔑 Alterar senha principal</h3>
    <p>Todos os arquivos do cofre serão recriptografados com a nova chave. Não feche o programa durante esta operação.</p>

    <div class="field">
      <label>SENHA ATUAL</label>
      <div class="input-shell"><span>🔑</span><input id="oldPass" type="password"></div>
    </div>
    <div class="field">
      <label>NOVA SENHA</label>
      <div class="input-shell"><span>◆</span><input id="newPass" type="password"></div>
    </div>
    <div class="field">
      <label>CONFIRMAR NOVA SENHA</label>
      <div class="input-shell"><span>✓</span><input id="newPass2" type="password"></div>
    </div>

    <div class="modal-actions">
      <button class="secondary" onclick="openSettings()">Cancelar</button>
      <button class="primary" style="width:auto;margin:0" onclick="changePassword()">Alterar senha</button>
    </div>
  `);
}

async function changePassword(){
  if(passwordBusy) return;
  const oldp=document.getElementById('oldPass')?.value || '';
  const np=document.getElementById('newPass')?.value || '';
  const cp=document.getElementById('newPass2')?.value || '';

  passwordBusy = true;
  try{
    toast('Recriptografando os arquivos com a nova chave...');
    const r=await api('change_password',oldp,np,cp);
    if(!r.ok) return toast(r.message,'error');
    closeModal();
    toast(r.message);
  }finally{
    passwordBusy = false;
  }
}

async function lockVault(){
  showConfirm('Bloquear cofre','Deseja encerrar a sessão e bloquear o acesso aos arquivos?',async ()=>{
    closeViewer();
    const r=await api('logout');
    closeModal();
    if(!r.ok) return toast(r.message,'error');
    state.logged_in=false;
    state.current_user=null;
    files=[];
    selectedVault=null;
    if(r.profiles) state.profiles=r.profiles;
    state.configured=(state.profiles||[]).length>0;
    toast(r.message);
    renderLogin('login');
  });
}

function showModal(html){
  closeModal();
  const back=document.createElement('div');
  back.className='modal-backdrop';
  back.id='modalBackdrop';
  back.innerHTML=`<div class="modal">${html}</div>`;
  back.addEventListener('mousedown',e=>{ if(e.target===back) closeModal(); });
  document.body.appendChild(back);
}
function closeModal(){
  const m=document.getElementById('modalBackdrop');
  if(m) m.remove();
}
function showConfirm(title,text,onYes){
  window.__confirmAction=onYes;
  showModal(`
    <h3>${esc(title)}</h3>
    <p>${esc(text)}</p>
    <div class="modal-actions">
      <button class="secondary" onclick="closeModal()">Cancelar</button>
      <button class="danger-primary" onclick="window.__confirmAction()">Confirmar</button>
    </div>
  `);
}

/* Fundo 3D otimizado: inicializa depois da interface e roda a ~30 FPS */
function startStars3D(){
  const canvas=document.getElementById('spaceCanvas');
  if(!canvas || canvas.dataset.started==='1') return;
  canvas.dataset.started='1';

  const ctx=canvas.getContext('2d', {alpha:true});
  let w=0,h=0,dpr=1,lastFrame=0;
  const stars=[];
  const COUNT=85;
  const FRAME_MS=1000/30;

  function resize(){
    dpr=Math.min(window.devicePixelRatio||1,1.5);
    w=window.innerWidth;h=window.innerHeight;
    canvas.width=Math.max(1,Math.floor(w*dpr));
    canvas.height=Math.max(1,Math.floor(h*dpr));
    canvas.style.width=w+'px';canvas.style.height=h+'px';
    ctx.setTransform(dpr,0,0,dpr,0,0);
  }

  function reset(s,randomZ=true){
    s.x=(Math.random()-.5)*w*1.8;
    s.y=(Math.random()-.5)*h*1.8;
    s.z=randomZ?Math.random()*900+60:900;
    s.pz=s.z;
  }

  function ensureStars(){
    stars.length=0;
    for(let i=0;i<COUNT;i++){ const s={}; reset(s,true); stars.push(s); }
  }

  function frame(ts){
    requestAnimationFrame(frame);
    if(ts-lastFrame < FRAME_MS) return;
    lastFrame=ts;

    ctx.clearRect(0,0,w,h);
    const cx=w/2,cy=h/2;

    for(const s of stars){
      s.pz=s.z;s.z-=1.8;
      if(s.z<10) reset(s,false);

      const scale=300/s.z;
      const x=cx+s.x*scale;
      const y=cy+s.y*scale;

      const pscale=300/s.pz;
      const px=cx+s.x*pscale;
      const py=cy+s.y*pscale;

      if(x<0||x>w||y<0||y>h){ reset(s,false); continue; }

      const a=Math.max(.12,1-s.z/950);
      ctx.beginPath();
      ctx.moveTo(px,py);ctx.lineTo(x,y);
      ctx.strokeStyle=`rgba(89,210,255,${a*.34})`;
      ctx.lineWidth=Math.max(.25,(1-s.z/950)*1.2);
      ctx.stroke();

      ctx.beginPath();
      ctx.arc(x,y,Math.max(.4,(1-s.z/950)*1.45),0,Math.PI*2);
      ctx.fillStyle=`rgba(184,233,255,${a*.82})`;
      ctx.fill();
    }
  }

  window.addEventListener('resize',()=>{
    resize();
    ensureStars();
  }, {passive:true});

  resize();
  ensureStars();
  requestAnimationFrame(frame);
}

function bootInterface(){
  // A interface aparece imediatamente. A ponte Python é preparada em
  // segundo plano e não gera mensagem de erro durante a inicialização.
  renderLogin();

  getBridgePromise().then(()=>{
    bridgeReady = true;
  });

  // A animação 3D começa depois do primeiro desenho da tela.
  setTimeout(startStars3D, 450);
}

window.addEventListener('pywebviewready', ()=>{
  bridgeReady = true;
});

if(document.readyState === 'loading'){
  document.addEventListener('DOMContentLoaded', bootInterface, {once:true});
}else{
  bootInterface();
}
</script>
</body>
</html>
"""


# ============================================================
# INÍCIO
# ============================================================

def main():
    global WINDOW

    ensure_directories()
    cleanup_temp()
    atexit.register(cleanup_temp)

    api = VaultAPI()

    # Estado mínimo inserido diretamente no HTML.
    # Assim o login aparece imediatamente, sem esperar a ponte JS <-> Python.
    profiles = load_profiles()
    boot_state = {
        "configured": bool(profiles),
        "profiles": [_profile_public(p) for p in profiles],
        "version": APP_VERSION,
        "app_name": APP_NAME,
    }
    html = HTML.replace("__BOOT_STATE__", json_for_html(boot_state))

    WINDOW = webview.create_window(
        f"{APP_NAME} V{APP_VERSION}",
        html=html,
        width=1280,
        height=800,
        min_size=(900, 620),
        resizable=True,
        background_color="#050816",
        # A seleção de texto é controlada pelo CSS (body: user-select:none),
        # o que permite copiar texto apenas dentro do visualizador.
        text_select=True,
    )

    api._set_window(WINDOW)

    # Expõe somente as funções realmente usadas pela interface. Evita entregar
    # o objeto VaultAPI inteiro ao js_api e impede que o pywebview percorra
    # atributos internos como a própria Window durante a criação da ponte JS.
    WINDOW.expose(
        api.get_state,
        api.create_profile,
        api.create_vault,
        api.login,
        api.logout,
        api.list_files,
        api.add_files,
        api.preview_file,
        api.extract_file,
        api.delete_file,
        api.get_file_details,
        api.change_password,
        api.open_vault_folder,
        api.get_storage_location,
    )

    # No Windows, o pywebview usa o WebView2/Edge Chromium quando disponível.
    webview.start(debug=False)


if __name__ == "__main__":
    main()