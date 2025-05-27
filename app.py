# app.py
# app.py
import streamlit as st
import pandas as pd
import sqlite3
import hashlib
from datetime import datetime, timedelta
import uuid
import os
from auth import authenticate, logout_user
from database import init_db, get_db_connection
from backup_manager import backup_database

# Configurações
DB_PATH = "users.db"
BACKUP_PATH = "backup.json"
MAX_INACTIVITY_DAYS = 30  # Dias de inatividade permitidos

# Inicialização do banco de dados
init_db()

def check_persisted_session():
    """Verifica sessões válidas no banco de dados"""
    conn = get_db_connection()
    try:
        c = conn.cursor()
        c.execute("""
            SELECT s.session_id, u.id, u.username, u.role 
            FROM sessions s
            JOIN users u ON s.user_id = u.id
            WHERE s.last_activity > ? AND u.is_active = 1
        """, (datetime.now() - timedelta(days=MAX_INACTIVITY_DAYS),))
        
        session = c.fetchone()
        if session:
            session_id, user_id, username, role = session
            st.session_state.user = {
                "id": user_id,
                "username": username,
                "role": role,
                "session_id": session_id
            }
            # Atualiza atividade
            c.execute("UPDATE sessions SET last_activity = ? WHERE session_id = ?",
                     (datetime.now(), session_id))
            conn.commit()
            return True
    finally:
        conn.close()
    return False

def show_login_form():
    """Exibe formulário de login"""
    with st.container(border=True):
        st.write("## Acesso ao Sistema")
        username = st.text_input("Usuário")
        password = st.text_input("Senha", type="password")
        
        if st.button("Entrar"):
            user = authenticate(username, password)
            if user:
                st.session_state.user = user
                backup_database()  # Cria backup após login
                st.rerun()
            else:
                st.error("Credenciais inválidas")

def manage_users():
    """Interface de gerenciamento de usuários (para admin)"""
    st.title("Gerenciamento de Usuários")
    # Implementação completa deste função...

def main_app():
    st.set_page_config(
        page_title="Catálogo de Motores",
        layout="wide",
        initial_sidebar_state="expanded"
    )

    # Verificação de autenticação
    if 'user' not in st.session_state:
        st.session_state.user = None
    
    if not st.session_state.user and not check_persisted_session():
        show_login_form()
        st.stop()

    # Sidebar
    with st.sidebar:
        if st.session_state.user:
            st.markdown(f"### 👤 {st.session_state.user['username']}")
            st.markdown(f"**Perfil:** {st.session_state.user['role']}")
            if st.button("🚪 Sair"):
                logout_user(st.session_state.user['id'])
                del st.session_state.user
                st.rerun()
        
        if st.session_state.user and st.session_state.user['role'] == 'admin':
            st.markdown("---")
            if st.toggle("Gerenciar Usuários"):
                manage_users()
                st.stop()

    # Conteúdo principal do app
    @st.cache_data
    def load_data():
        try:
            return pd.read_excel("motores.xlsx")
        except Exception as e:
            st.error(f"Erro ao carregar dados: {str(e)}")
            return pd.DataFrame()

    df = load_data()
    
    if not df.empty:
        # Interface de busca e exibição (mantida conforme seu código original)
        # ... (seu código existente de exibição de motores)
    else:
        st.warning("Nenhum dado foi carregado. Verifique o arquivo de origem.")

    # Rodapé
    st.markdown("---")
    st.caption("Sistema de Catálogo de Motores - © 2025")

if __name__ == "__main__":
    main_app()
