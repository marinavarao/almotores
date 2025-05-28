# database.py
import sqlite3
from datetime import datetime

DB_PATH = "users.db"

def get_db_connection():
    """Retorna uma conexão com o banco de dados"""
    return sqlite3.connect(DB_PATH)

def init_db():
    """Inicializa o banco de dados"""
    conn = get_db_connection()
    try:
        c = conn.cursor()
        
        # Tabela de usuários
        c.execute('''CREATE TABLE IF NOT EXISTS users
                    (id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT UNIQUE NOT NULL,
                    password_hash TEXT NOT NULL,
                    role TEXT NOT NULL,
                    is_active BOOLEAN DEFAULT 1,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
        
        # Tabela de sessões
        c.execute('''CREATE TABLE IF NOT EXISTS sessions
                    (session_id TEXT PRIMARY KEY,
                    user_id INTEGER NOT NULL,
                    login_time TIMESTAMP NOT NULL,
                    last_activity TIMESTAMP NOT NULL,
                    FOREIGN KEY(user_id) REFERENCES users(id))''')
        
        conn.commit()
    finally:
        conn.close()
