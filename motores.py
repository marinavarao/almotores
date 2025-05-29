# Configuração da página
# cd C:\Users\Usuário\Documents
# streamlit run motores.py
import streamlit as st
import pandas as pd
import sqlite3
import hashlib
from datetime import datetime, timedelta  # Importação corrigida
import uuid
import os

# Configurações
USER_DB = "users.db"
MAX_ATTEMPTS = 3

# --- Sistema de Login Multi-Usuário ---
def init_db():
    conn = sqlite3.connect(USER_DB)
    c = conn.cursor()
    
    # Tabela de usuários
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                 username TEXT UNIQUE NOT NULL,
                 password_hash TEXT NOT NULL,
                 role TEXT NOT NULL,
                 is_active INTEGER DEFAULT 1)''')
    
    # Tabela de sessões
    c.execute('''CREATE TABLE IF NOT EXISTS active_sessions
                 (session_id TEXT PRIMARY KEY,
                  user_id INTEGER NOT NULL,
                  login_time TIMESTAMP NOT NULL,
                  last_activity TIMESTAMP NOT NULL,
                  ip_address TEXT,
                  FOREIGN KEY(user_id) REFERENCES users(id))''')

    
    # Inserir admin padrão se não existir
    try:
        admin_hash = hashlib.sha256("admin123".encode()).hexdigest()
        c.execute("INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
                  ("admin", admin_hash, "admin"))
        conn.commit()
    except sqlite3.IntegrityError:
        pass
    finally:
        conn.close()

def authenticate(username, password):
    conn = sqlite3.connect(USER_DB)
    c = conn.cursor()
    c.execute("SELECT id, password_hash, role FROM users WHERE username = ? AND is_active = 1", (username,))
    user = c.fetchone()
    conn.close()
    
    if user and hashlib.sha256(password.encode()).hexdigest() == user[1]:
        return {"id": user[0], "username": username, "role": user[2]}
    return None

def login_form():
    if 'user' not in st.session_state:
        st.session_state.user = None
        st.session_state.attempts = 0

    if st.session_state.user:
        return True

    with st.form("login"):
        st.write("## Autenticação")
        username = st.text_input("Usuário")
        password = st.text_input("Senha", type="password")
        
        if st.form_submit_button("Entrar"):
            if st.session_state.attempts >= MAX_ATTEMPTS:
                st.error("Muitas tentativas falhas. Tente novamente mais tarde.")
                return False
            
            user = authenticate(username, password)
            if user:
                st.session_state.user = user
                st.rerun()
            else:
                st.session_state.attempts += 1
                st.error(f"Credenciais inválidas. Tentativa {st.session_state.attempts}/{MAX_ATTEMPTS}")
    return False

def login(username, password):
    user, error = authenticate(username, password)
    if user:
        try:
            conn = sqlite3.connect(USER_DB)
            c = conn.cursor()
            
            session_id = str(uuid.uuid4())
            ip = st.experimental_get_query_params().get('client', ['unknown'])[0]
            
            # Remove sessões antigas do mesmo usuário
            c.execute('''DELETE FROM active_sessions 
                        WHERE user_id = ?''', (user['id'],))
            
            # Insere nova sessão
            c.execute('''INSERT INTO active_sessions 
                        (session_id, user_id, login_time, last_activity, ip_address)
                        VALUES (?, ?, ?, ?, ?)''',
                     (session_id, user['id'], datetime.now(), datetime.now(), ip))
            
            conn.commit()
            
            # Atualiza a sessão
            st.session_state.user = user
            st.session_state.session_id = session_id
            st.rerun()
            
        except Exception as e:
            st.error(f"Erro ao iniciar sessão: {str(e)}")
        finally:
            if conn:
                conn.close()
    elif error:
        st.error(error)

def check_active_session():
    # Verifica primeiro se já está na sessão do Streamlit
    if 'user' in st.session_state and 'session_id' in st.session_state:
        try:
            conn = sqlite3.connect(USER_DB)
            c = conn.cursor()
            
            # Atualiza o timestamp de atividade
            c.execute('''UPDATE active_sessions 
                        SET last_activity = ?
                        WHERE session_id = ?''',
                     (datetime.now(), st.session_state.session_id))
            conn.commit()
            return True
        except Exception as e:
            st.error(f"Erro ao verificar sessão: {str(e)}")
            return False
        finally:
            if conn:
                conn.close()
    
    # Se não há sessão no state, verifica no banco de dados
    try:
        conn = sqlite3.connect(USER_DB)
        c = conn.cursor()
        
        # Verifica sessões válidas (últimas 8 horas)
        c.execute('''SELECT user_id, session_id 
                    FROM active_sessions 
                    WHERE last_activity > ?''',
                (datetime.now() - timedelta(hours=8),))
        
        active_session = c.fetchone()
        
        if active_session:
            user_id, session_id = active_session
            c.execute('''SELECT username, role FROM users 
                        WHERE id = ? AND is_active = 1''', (user_id,))
            user_data = c.fetchone()
            
            if user_data:
                # Restaura a sessão
                st.session_state.user = {
                    'id': user_id,
                    'username': user_data[0],
                    'role': user_data[1]
                }
                st.session_state.session_id = session_id
                return True
    except Exception as e:
        st.error(f"Erro ao recuperar sessão: {str(e)}")
        return False
    finally:
        if conn:
            conn.close()
    
    return False
    
def logout():
    if 'session_id' in st.session_state:
        try:
            conn = sqlite3.connect(USER_DB)
            c = conn.cursor()
            c.execute('''DELETE FROM active_sessions 
                        WHERE session_id = ?''',
                     (st.session_state.session_id,))
            conn.commit()
        except Exception as e:
            st.error(f"Erro ao encerrar sessão: {str(e)}")
        finally:
            if conn:
                conn.close()
    
    # Limpa a sessão
    keys = list(st.session_state.keys())
    for key in keys:
        del st.session_state[key]
    
    st.rerun()
    
# --- Aplicação Principal ---
def main_app():
    st.set_page_config(
        page_title="Catálogo de Motores",
        layout="wide",
        initial_sidebar_state="expanded"
    )

    # Sidebar com informações do usuário
    with st.sidebar:
        if st.session_state.user:
            st.markdown(f"### 👤 {st.session_state.user['username']}")
            st.markdown(f"**Perfil:** {st.session_state.user['role']}")
            if st.button("🚪 Sair"):
                logout()
        
        if st.session_state.user and st.session_state.user['role'] == 'admin':
            st.markdown("---")
            if st.toggle("Gerenciar Usuários"):
                manage_users()
                st.stop()

    # Carregar dados
    @st.cache_data
    def load_data():
        try:
            return pd.read_excel("motores.xlsx")
        except FileNotFoundError:
            st.error("Arquivo 'motores.xlsx' não encontrado. Verifique o caminho.")
            return pd.DataFrame()
        except Exception as e:
            st.error(f"Erro ao carregar dados: {str(e)}")
            return pd.DataFrame()

    df = load_data()

    if not df.empty:
        st.title("Catálogo de Motores Elétricos")
        
        # --- BUSCA POR ATIVO OU POSIÇÃO ---
        col1, col2 = st.columns([3, 1])
        
        with col1:
            # Campo de busca geral
            search_term = st.text_input(
                "Buscar por TAG ATIVO ou POSIÇÃO:",
                placeholder="Digite parte do TAG ou POSIÇÃO...",
                key="general_search"
            )
        
        with col2:
            # Seletor do tipo de busca
            search_type = st.selectbox(
                "Tipo de busca:",
                options=["TAG ATIVO", "TAG ATUAL (POSIÇÃO)"],
                index=0
            )
        
        # Filtra os dados conforme o termo de busca
        if search_term:
            if search_type == "TAG ATIVO":
                mask = df["TAG ATIVO"].astype(str).str.contains(search_term, case=False, na=False)
            else:
                mask = df["TAG ATUAL"].astype(str).str.contains(search_term, case=False, na=False)
            
            filtered_df = df[mask]
        else:
            filtered_df = df
        
        # Verifica se há resultados
        if len(filtered_df) == 0:
            st.warning("Nenhum motor encontrado com estes critérios")
            st.stop()
        
        # Mostra lista resumida de resultados
        st.subheader("Resultados da Busca")
        
        # Cria uma coluna combinada para melhor visualização
        filtered_df["TAG/POSIÇÃO"] = filtered_df["TAG ATIVO"] + " | " + filtered_df["TAG ATUAL"]
        
        # Seleciona apenas as colunas relevantes para exibição
        display_cols = ["TAG/POSIÇÃO", "DESCRIÇÃO", "LOCAL", "POTÊNCIA (kW)"]
        display_df = filtered_df[display_cols]
        
        # Formatação da tabela
        st.dataframe(
            display_df,
            use_container_width=True,
            hide_index=True,
            column_config={
                "TAG/POSIÇÃO": "Identificação",
                "DESCRIÇÃO": "Descrição",
                "LOCAL": "Localização",
                "POTÊNCIA (kW)": "Potência (kW)"
            }
        )
        
        # --- SELEÇÃO DO ATIVO PARA DETALHES ---
        st.markdown("---")
        st.subheader("Detalhes do Motor")
        
        # Cria opções para o selectbox no formato "TAG ATIVO | TAG ATUAL - DESCRIÇÃO"
        options = [
            f"{row['TAG ATIVO']} | {row['TAG ATUAL']} - {row['DESCRIÇÃO']}" 
            for _, row in filtered_df.iterrows()
        ]
        
        selected_option = st.selectbox(
            "Selecione um motor para ver os detalhes:",
            options=options,
            index=0
        )
        
        # Extrai o TAG ATIVO da opção selecionada
        selected_tag_ativo = selected_option.split(" | ")[0]
        
        # Filtra os dados para o motor selecionado
        motor_data = df[df["TAG ATIVO"] == selected_tag_ativo].iloc[0]
        
        # --- EXIBIÇÃO DOS DADOS ---
        # Organização em abas
        tab1, tab2, tab3 = st.tabs(["Informações Básicas", "Especificações Técnicas", "Detalhes Mecânicos"])
        
        with tab1:
            col1, col2 = st.columns(2)
            with col1:
                st.markdown(f"""
                **TAG Ativo:** {motor_data["TAG ATIVO"]}  
                **TAG Atual (Posição):** {motor_data["TAG ATUAL"]}  
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
    
# --- Gerenciamento de Usuários ---
def manage_users():
    st.title("Gerenciamento de Usuários")
    
    conn = sqlite3.connect(USER_DB)
    
    # Adicionar usuário
    with st.expander("➕ Novo Usuário"):
        with st.form("add_user"):
            username = st.text_input("Nome de usuário")
            password = st.text_input("Senha", type="password")
            role = st.selectbox("Perfil", ["operador", "supervisor", "admin"])
            
            if st.form_submit_button("Salvar"):
                if username and password:
                    try:
                        hashed = hashlib.sha256(password.encode()).hexdigest()
                        conn.execute("INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
                                     (username, hashed, role))
                        conn.commit()
                        st.success("Usuário criado!")
                    except sqlite3.IntegrityError:
                        st.error("Usuário já existe")
    
    # Listar usuários
    st.subheader("Usuários Existentes")
    users = pd.read_sql("SELECT id, username, role, is_active FROM users", conn)
    st.dataframe(users, use_container_width=True)
    
    st.markdown("---")
    st.subheader("Modificar Usuários")
    
    # Selecionar usuário para edição
    users_df = pd.read_sql("SELECT id, username, role FROM users WHERE username != 'admin'", conn)
    selected_user = st.selectbox(
        "Selecione um usuário para modificar:",
        options=users_df['username'],
        index=None,
        key="user_selector"
    )
    
    if selected_user:
        user_data = users_df[users_df['username'] == selected_user].iloc[0]
        
        col1, col2 = st.columns(2)
        
        with col1:
            # EDITAR SENHA
            with st.form(f"edit_pw_{user_data['id']}"):
                st.write("### Alterar Senha")
                new_password = st.text_input("Nova senha", type="password", key=f"new_pw_{user_data['id']}")
                if st.form_submit_button("Atualizar Senha"):
                    if new_password:
                        hashed_pw = hashlib.sha256(new_password.encode()).hexdigest()
                        conn.execute("UPDATE users SET password_hash = ? WHERE id = ?", 
                                    (hashed_pw, user_data['id']))
                        conn.commit()
                        st.success("Senha atualizada!")
                    else:
                        st.error("Digite uma nova senha")
        
        with col2:
            # EXCLUIR USUÁRIO
            with st.form(f"delete_{user_data['id']}"):
                st.write("### Excluir Usuário")
                confirm = st.checkbox("Confirmar exclusão")
                if st.form_submit_button("🗑️ Excluir"):
                    if confirm:
                        conn.execute("DELETE FROM users WHERE id = ?", (user_data['id'],))
                        conn.commit()
                        st.success(f"Usuário {selected_user} excluído!")
                        st.rerun()
                    else:
                        st.warning("Marque a confirmação")
    
    conn.close()


# --- Ponto de Entrada ---
if __name__ == "__main__":
    init_db()
    
    if not check_active_session():
        if not login_form():
            st.stop()
    
    main_app()
