# auth.py
from datetime import datetime
from database import get_db_connection
import hashlib
import uuid

def authenticate(username, password):
    """Autentica um usuário"""
    conn = get_db_connection()
    try:
        c = conn.cursor()
        password_hash = hashlib.sha256(password.encode()).hexdigest()
        
        c.execute('''SELECT id, username, role FROM users 
                  WHERE username = ? AND password_hash = ? AND is_active = 1''',
                  (username, password_hash))
        
        user = c.fetchone()
        if user:
            # Cria nova sessão
            session_id = str(uuid.uuid4())
            c.execute('''INSERT INTO sessions 
                      (session_id, user_id, login_time, last_activity)
                      VALUES (?, ?, ?, ?)''',
                      (session_id, user[0], datetime.now(), datetime.now()))
            conn.commit()
            return {
                "id": user[0],
                "username": user[1],
                "role": user[2],
                "session_id": session_id
            }
    finally:
        conn.close()
    return None

def logout_user(user_id=None, session_id=None):
    """Remove a sessão do usuário com tratamento robusto"""
    conn = None
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        if session_id:
            cursor.execute("DELETE FROM sessions WHERE session_id = ?", (session_id,))
        elif user_id:
            cursor.execute("DELETE FROM sessions WHERE user_id = ?", (user_id,))
        
        conn.commit()
        return True
    except sqlite3.Error as e:
        print(f"Erro ao fazer logout: {str(e)}")
        return False
    finally:
        if conn:
            conn.close()
