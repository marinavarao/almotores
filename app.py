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
from database import create_user  # Adicione esta importação

# Configurações
DB_PATH = "users.db"
BACKUP_PATH = "backup.json"
MAX_INACTIVITY_DAYS = 30  # Dias de inatividade permitidos

# Inicialização do banco de dados
init_db()

# Cria usuário admin padrão se não existir
try:
    create_user("admin", "admin123", role="admin")
except:
    pass  # Usuário já existe

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

# Adicione esta função no app.py
def manage_users():
    """Interface de gerenciamento de usuários"""
    st.title("Gerenciamento de Usuários")
    
    # Abas para diferentes operações
    tab1, tab2, tab3 = st.tabs(["Criar Usuário", "Listar Usuários", "Editar Usuários"])
    
    with tab1:
        with st.form("create_user_form"):
            st.write("### Novo Usuário")
            username = st.text_input("Nome de usuário*")
            password = st.text_input("Senha*", type="password")
            full_name = st.text_input("Nome completo")
            email = st.text_input("Email")
            role = st.selectbox("Tipo de usuário", ["user", "admin"])
            
            if st.form_submit_button("Criar Usuário"):
                if username and password:
                    if create_user(username, password, full_name, email, role):
                        st.success(f"Usuário {username} criado com sucesso!")
                    else:
                        st.error("Nome de usuário já existe")
                else:
                    st.warning("Campos obrigatórios marcados com *")
    
    with tab2:
        try:
            conn = get_db_connection()
            # Consulta segura usando parâmetros
            query = """
                SELECT id, username, full_name, email, role, is_active 
                FROM users
                ORDER BY username
            """
            users = pd.read_sql(query, conn)
            st.dataframe(users, hide_index=True)
        except Exception as e:
            st.error(f"Erro ao acessar o banco de dados: {str(e)}")
        finally:
            if 'conn' in locals():
                conn.close()
    
    with tab3:
        conn = get_db_connection()
        user_list = pd.read_sql("SELECT id, username FROM users", conn)['username'].tolist()
        selected_user = st.selectbox("Selecionar usuário", user_list)
        
        if selected_user:
            user_data = pd.read_sql(f"SELECT * FROM users WHERE username = '{selected_user}'", conn).iloc[0]
            
            with st.form("edit_user_form"):
                st.write(f"Editando: {selected_user}")
                new_username = st.text_input("Nome de usuário", value=user_data['username'])
                new_role = st.selectbox("Tipo de usuário", ["user", "admin"], 
                                      index=0 if user_data['role'] == "user" else 1)
                is_active = st.checkbox("Ativo", value=bool(user_data['is_active']))
                new_password = st.text_input("Nova senha (deixe em branco para manter)", type="password")
                
                if st.form_submit_button("Salvar Alterações"):
                    try:
                        if new_password:
                            password_hash = hashlib.sha256(new_password.encode()).hexdigest()
                            conn.execute('''UPDATE users SET 
                                        username = ?, role = ?, is_active = ?, password_hash = ?
                                        WHERE id = ?''',
                                        (new_username, new_role, int(is_active), password_hash, user_data['id']))
                        else:
                            conn.execute('''UPDATE users SET 
                                        username = ?, role = ?, is_active = ?
                                        WHERE id = ?''',
                                        (new_username, new_role, int(is_active), user_data['id']))
                        conn.commit()
                        st.success("Usuário atualizado!")
                        st.rerun()
                    except sqlite3.IntegrityError:
                        st.error("Nome de usuário já existe")
        conn.close()

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
         # --- BUSCA POR TAG ---
            st.title("Motores Elétricos")
            
            # Campo de busca por digitação
            search_term = st.text_input(
                "Digite a TAG do motor:",
                placeholder="Comece a digitar a TAG...",
                key="tag_search"
            )
            
            try:
                # Filtra as opções com base no que foi digitado
                if search_term:
                    mask = df["TAG ATIVO"].astype(str).str.contains(str(search_term), case=False, na=False)
                    filtered_tags = df.loc[mask, "TAG ATIVO"].unique()
                else:
                    filtered_tags = df["TAG ATIVO"].unique()
                
                # Verifica se há resultados
                if len(filtered_tags) == 0:
                    st.warning("Nenhum motor encontrado com esta TAG")
                    st.stop()
                    
                # Selecionador de TAG com as opções filtradas
                selected_tag = st.selectbox(
                    "Ou selecione a TAG do motor:",
                    options=filtered_tags,
                    index=0
                )
                
                # Filtra os dados
                motor_data = df[df["TAG ATIVO"] == selected_tag].iloc[0]
                
            except Exception as e: 
                st.error(f"Erro ao filtrar dados: {str(e)}")
                st.stop()
            
            # --- EXIBIÇÃO DOS DADOS ---
            st.markdown("---")
            st.subheader(f"Dados Técnicos - {selected_tag}")
            
            # Organização em abas (mantido igual)
            tab1, tab2, tab3 = st.tabs(["Informações Básicas", "Especificações Técnicas", "Detalhes Mecânicos"])
            
            with tab1:
                col1, col2 = st.columns(2)
                with col1:
                    st.markdown(f"""
                    **Posição:** {motor_data["TAG ATUAL"]}  
                    **Descrição:** {motor_data["DESCRIÇÃO"]}  
                    **Localização:** {motor_data["LOCAL"]}  
                    **Área de Instalação:** {motor_data["ÁREA"]}  
                    """)
                with col2:
                    st.markdown(f"""
                    **Fabricante:** {motor_data["FABRICANTE"]}  
                    **Modelo:** {motor_data["MODELO"]}  
                    **N° Série:** {motor_data["N° DE SÉRIE"]}  
                    **Ano Fabricação:** {motor_data["ANO FAB."]}  
                    """)
            
            with tab2:
                col1, col2 = st.columns(2)
                with col1:
                    st.markdown(f"""
                    **Potência:** {motor_data["POTÊNCIA (kW)"]} kW  
                    **Tensão:** {motor_data["TENSÃO (V)"]} V  
                    **Corrente:** {motor_data["CORRENTE(A)"]} A  
                    **Frequência:** {motor_data["FREQ.(Hz)"]} Hz  
                    """)
                with col2:
                    st.markdown(f"""
                    **N° Fases:** {motor_data["Nº DE FASES"]}  
                    **N° Polos:** {motor_data["N° POLOS"]}  
                    **RPM:** {motor_data["RPM"]}  
                    **Grau IP:** {motor_data["GRAU IP"]}  
                    """)
            
            with tab3:
                col1, col2 = st.columns(2)
                with col1:
                    st.markdown(f"""
                    **Carcaça:** {motor_data["CARCAÇA"]}  
                    **Peso:** {motor_data["PESO (kg)"]} kg  
                    **Posição Instalação:** {motor_data["POSIÇÃO DE INSTALAÇÃO"]}  
                    """)
                with col2:
                    st.markdown(f"""
                    **Rolamento Dianteiro:** {motor_data["ROLAMENTO DIANTEIRO"]}  
                    **Rolamento Traseiro:** {motor_data["ROLAMENTO TRASEIRO"]}  
                    **Tipo Graxa:** {motor_data["GRAXA TIPO"]}  
                    """)
            
            # Botão para mostrar todos os dados (opcional)
            if st.button("Mostrar todos os dados brutos"):
                st.write(motor_data)
    else:
        st.warning("Nenhum dado foi carregado. Verifique o arquivo de origem.")

    # Rodapé
    st.markdown("---")
    st.caption("Sistema de Catálogo de Motores - © 2025")

if __name__ == "__main__":
    main_app()
