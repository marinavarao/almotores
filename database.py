# database.py
import sqlite3
import hashlib
from datetime import datetime

DB_PATH = "users.db"

def get_db_connection():
    """Retorna uma conexão com tratamento de erros"""
    try:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row  # Para acesso por nome de coluna
        return conn
    except sqlite3.Error as e:
        st.error(f"Erro ao conectar ao banco de dados: {str(e)}")
        raise

def init_db():
    """Inicializa o banco de dados com tabelas necessárias"""
    conn = get_db_connection()
    try:
        c = conn.cursor()
        
        # Tabela de usuários
        c.execute('''CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    full_name TEXT,
                    email TEXT,
                    role TEXT NOT NULL DEFAULT 'user',
                    is_active BOOLEAN DEFAULT 1,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )''')
        
        # Tabela de sessões
        c.execute('''CREATE TABLE IF NOT EXISTS sessions (
                    session_id TEXT PRIMARY KEY,
                    user_id INTEGER NOT NULL,
                    login_time TIMESTAMP NOT NULL,
                    last_activity TIMESTAMP NOT NULL,
                    ip_address TEXT,
                    FOREIGN KEY(user_id) REFERENCES users(id)
                    )''')
        
        # Cria usuário admin padrão se não existir
        try:
            admin_hash = hashlib.sha256("admin123".encode()).hexdigest()
            c.execute("INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
                     ("admin", admin_hash, "admin"))
        except sqlite3.IntegrityError:
            pass  # Usuário admin já existe
        
        conn.commit()
    finally:
        conn.close()

def create_user(username, password, full_name="", email="", role="user"):
    """Cria um novo usuário no banco de dados"""
    conn = get_db_connection()
    try:
        password_hash = hashlib.sha256(password.encode()).hexdigest()
        conn.execute("INSERT INTO users (username, password_hash, full_name, email, role) VALUES (?, ?, ?, ?, ?)",
                    (username, password_hash, full_name, email, role))
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False  # Usuário já existe
    finally:
        conn.close()

def check_table_exists(table_name):
    """Verifica se uma tabela existe no banco"""
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute(f"SELECT name FROM sqlite_master WHERE type='table' AND name='{table_name}'")
        return cursor.fetchone() is not None
    finally:
        conn.close()
