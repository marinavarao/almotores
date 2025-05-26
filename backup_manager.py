# backup_manager.py
import sqlite3
import json
import os
from datetime import datetime

def export_to_json():
    conn = sqlite3.connect('users.db')
    
    data = {
        'users': [],
        'sessions': [],
        'backup_timestamp': str(datetime.now())
    }
    
    # Exporta usuários
    cursor = conn.execute('SELECT * FROM users')
    for row in cursor:
        data['users'].append(dict(row))
    
    # Exporta sessões ativas
    cursor = conn.execute('''SELECT * FROM sessions 
                          WHERE expires_at > ?''', 
                          (datetime.now(),))
    for row in cursor:
        data['sessions'].append(dict(row))
    
    conn.close()
    
    with open('backup.json', 'w') as f:
        json.dump(data, f, indent=2, default=str)
    
    # Simula commit no Git (configure seu repositório real)
    os.system('git add backup.json')
    os.system(f'git commit -m "Backup automático {datetime.now().date()}"')
    os.system('git push origin main')