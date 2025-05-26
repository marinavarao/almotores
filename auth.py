# auth.py
from datetime import datetime, timedelta

def login(username, password):
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    
    # Verifica credenciais
    c.execute('''SELECT id, password_hash FROM users 
               WHERE username = ? AND is_active = 1''', (username,))
    user = c.fetchone()
    
    if user and check_password_hash(user[1], password):
        session_id = generate_session_id()
        expires_at = datetime.now() + timedelta(days=30)  # Sessão de 30 dias
        
        # Registra sessão
        c.execute('''INSERT INTO sessions 
                   (session_id, user_id, login_time, expires_at, ip_address)
                   VALUES (?, ?, ?, ?, ?)''',
                   (session_id, user[0], datetime.now(), expires_at, get_client_ip()))
        
        conn.commit()
        conn.close()
        return session_id
    return None