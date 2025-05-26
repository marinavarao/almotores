# database.py
import sqlite3
from datetime import datetime, timedelta

def init_db():
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    
    # Tabela de usuários (persistente)
    c.execute('''CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        role TEXT NOT NULL,
        is_active BOOLEAN DEFAULT 1,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        last_login TIMESTAMP
    )''')
    
    # Tabela de sessões (com validade estendida)
    c.execute('''CREATE TABLE IF NOT EXISTS sessions (
        session_id TEXT PRIMARY KEY,
        user_id INTEGER NOT NULL,
        login_time TIMESTAMP NOT NULL,
        expires_at TIMESTAMP NOT NULL,  # Validade de 30 dias
        ip_address TEXT,
        FOREIGN KEY(user_id) REFERENCES users(id)
    )''')
    
    conn.commit()
    conn.close()