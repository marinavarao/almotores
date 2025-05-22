# Configuração da página
# cd C:\Users\Usuário\Documents
# streamlit run motores.py
import streamlit as st
import pandas as pd
import sqlite3
import hashlib
from datetime import datetime

# Configuração do banco de dados
USER_DB = "users.db"

def init_db():
    conn = sqlite3.connect(USER_DB)
    c = conn.cursor()
    
    # Tabela de usuários
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                 username TEXT UNIQUE NOT NULL,
                 password_hash TEXT NOT NULL,
                 full_name TEXT,
                 email TEXT,
                 role TEXT NOT NULL,
                 is_active INTEGER DEFAULT 1,
                 created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
    
    # Tabela de logs de acesso
    c.execute('''CREATE TABLE IF NOT EXISTS access_logs
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                 user_id INTEGER,
                 login_time TIMESTAMP,
                 logout_time TIMESTAMP,
                 ip_address TEXT,
                 success INTEGER,
                 FOREIGN KEY(user_id) REFERENCES users(id))''')
    
    # Inserir usuário admin padrão se não existir
    try:
        admin_hash = hashlib.sha256("admin123".encode()).hexdigest()
        c.execute("INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
                  ("admin", admin_hash, "admin"))
    except sqlite3.IntegrityError:
        pass
    
    conn.commit()
    conn.close()

init_db()

def authenticate_user(username, password):
    conn = sqlite3.connect(USER_DB)
    c = conn.cursor()
    
    c.execute("SELECT id, password_hash, role, is_active FROM users WHERE username = ?", (username,))
    user = c.fetchone()
    conn.close()
    
    if not user:
        return None, "Usuário não encontrado"
    
    if not user[3]:  # is_active
        return None, "Usuário desativado"
    
    hashed_input = hashlib.sha256(password.encode()).hexdigest()
    if hashed_input == user[1]:
        return {"id": user[0], "username": username, "role": user[2]}, None
    else:
        return None, "Senha incorreta"

def login_component():
    if 'user' not in st.session_state:
        st.session_state.user = None
        st.session_state.login_attempts = 0
        st.session_state.last_attempt = None
    
    if st.session_state.user:
        return True
    
    with st.container(border=True):
        st.markdown("### Acesso ao Sistema")
        
        if (st.session_state.login_attempts >= 3 and 
            (datetime.now() - st.session_state.last_attempt).seconds < 300):
            st.error("Muitas tentativas falhas. Tente novamente em 5 minutos.")
            return False
        
        username = st.text_input("Usuário")
        password = st.text_input("Senha", type="password")
        
        if st.button("Entrar"):
            user, error = authenticate_user(username, password)
            if user:
                st.session_state.user = user
                log_access(user['id'], True)
                st.rerun()
            else:
                st.session_state.login_attempts += 1
                st.session_state.last_attempt = datetime.now()
                log_access(None, False, username)
                st.error(f"Falha no login: {error}")
    
    return False

def user_management():
    if not (st.session_state.user and st.session_state.user['role'] == 'admin'):
        st.warning("Acesso restrito a administradores")
        return
    
    st.title("Gerenciamento de Usuários")
    
    tab1, tab2, tab3 = st.tabs(["Adicionar Usuário", "Listar Usuários", "Editar Usuários"])
    
    with tab1:
        with st.form("add_user_form"):
            st.write("### Cadastrar Novo Usuário")
            new_username = st.text_input("Nome de usuário*")
            new_password = st.text_input("Senha*", type="password")
            full_name = st.text_input("Nome completo")
            email = st.text_input("Email")
            role = st.selectbox("Perfil*", ["operador", "supervisor", "admin"])
            
            if st.form_submit_button("Cadastrar"):
                if not new_username or not new_password:
                    st.error("Campos obrigatórios marcados com *")
                else:
                    try:
                        conn = sqlite3.connect(USER_DB)
                        c = conn.cursor()
                        hashed_pw = hashlib.sha256(new_password.encode()).hexdigest()
                        c.execute("INSERT INTO users (username, password_hash, full_name, email, role) VALUES (?, ?, ?, ?, ?)",
                                  (new_username, hashed_pw, full_name, email, role))
                        conn.commit()
                        st.success(f"Usuário {new_username} cadastrado com sucesso!")
                    except sqlite3.IntegrityError:
                        st.error("Nome de usuário já existe")
                    finally:
                        conn.close()
    
    with tab2:
        conn = sqlite3.connect(USER_DB)
        users = pd.read_sql("SELECT id, username, full_name, role, is_active FROM users", conn)
        conn.close()
        
        st.dataframe(users, use_container_width=True,
                    column_config={
                        "is_active": st.column_config.CheckboxColumn("Ativo"),
                        "id": None
                    },
                    hide_index=True)
    
    with tab3:
        conn = sqlite3.connect(USER_DB)
        users = pd.read_sql("SELECT id, username, role, is_active FROM users", conn)
        conn.close()
        
        selected_user = st.selectbox("Selecionar usuário", 
                                   users['username'],
                                   index=None)
        
        if selected_user:
            user_data = users[users['username'] == selected_user].iloc[0]
            
            with st.form("edit_user_form"):
                st.write(f"Editando: {selected_user}")
                new_role = st.selectbox("Perfil", ["operador", "supervisor", "admin"], 
                                      index=["operador", "supervisor", "admin"].index(user_data['role']))
                is_active = st.checkbox("Ativo", value=bool(user_data['is_active']))
                new_password = st.text_input("Nova senha (deixe em branco para manter)", type="password")
                
                if st.form_submit_button("Salvar alterações"):
                    conn = sqlite3.connect(USER_DB)
                    c = conn.cursor()
                    
                    if new_password:
                        hashed_pw = hashlib.sha256(new_password.encode()).hexdigest()
                        c.execute("UPDATE users SET role = ?, is_active = ?, password_hash = ? WHERE id = ?",
                                (new_role, int(is_active), hashed_pw, user_data['id']))
                    else:
                        c.execute("UPDATE users SET role = ?, is_active = ? WHERE id = ?",
                                (new_role, int(is_active), user_data['id']))
                    
                    conn.commit()
                    conn.close()
                    st.success("Alterações salvas!")

def main_app():
    if not login_component():
        st.stop()
    
    # Barra lateral com informações do usuário
    with st.sidebar:
        st.markdown(f"### 👤 {st.session_state.user['username']}")
        st.markdown(f"**Perfil:** {st.session_state.user['role']}")
        
        if st.button("🔄 Atualizar Dados"):
            st.cache_data.clear()
            st.rerun()
            
        if st.button("🚪 Sair"):
            log_logout(st.session_state.user['id'])
            del st.session_state.user
            st.rerun()
        
        # Mostrar gerenciamento de usuários apenas para admin
        if st.session_state.user['role'] == 'admin':
            if st.toggle("Mostrar Gerenciamento"):
                user_management()
                st.stop()
    
# Configurações de segurança
PASSWORD = "kepla321"  # Troque por uma senha complexa
MAX_ATTEMPTS = 3
LOG_FILE = "access_log.txt"

# Verificação de senha
def check_password():
    if 'authenticated' not in st.session_state:
        st.session_state.authenticated = False
        st.session_state.attempts = 0
    
    if not st.session_state.authenticated:
        password = st.text_input("Digite a senha de acesso:", type="password")
        
        if st.button("Acessar"):
            if password == PASSWORD:
                st.session_state.authenticated = True
                log_access(True)
                st.rerun()
            else:
                st.session_state.attempts += 1
                log_access(False)
                if st.session_state.attempts >= MAX_ATTEMPTS:
                    st.error("Número máximo de tentativas excedido")
                    st.stop()
                else:
                    st.error(f"Senha incorreta. Tentativas restantes: {MAX_ATTEMPTS - st.session_state.attempts}")
        st.stop()

# Log de acesso
def log_access(success):
    with open(LOG_FILE, "a") as f:
        f.write(f"{datetime.now()} - {'SUCCESS' if success else 'FAILED'} - {st.experimental_get_query_params().get('client', ['unknown'])[0]}\n")

# Seu código original (adaptado)
def main_app():
    st.set_page_config(
            page_title="Catálogo de Motores - Busca por TAG",
            layout="wide",
        )

    @st.cache_data
    def load_data():

            try:
                # ATENÇÃO: Substitua pelo caminho correto do seu arquivo
                return pd.read_excel(r"C:\Users\Usuário\Documents\motores.xlsx")
            except FileNotFoundError:
                st.error("Arquivo 'motores.xlsx' não encontrado. Verifique o caminho.")
                return pd.DataFrame()
            except Exception as e:
                st.error(f"Erro ao carregar dados: {str(e)}")
                return pd.DataFrame()

        # Carrega os dados
    df = load_data()

    if not df.empty:
            # --- BUSCA POR TAG ---
            st.title("Motores Elétricos")
            
            # Campo de busca por digitação
            search_term = st.text_input(
                "Digite a POSIÇÃO do motor:",
                placeholder="Comece a digitar a POSIÇÃO...",
                key="tag_search"
            )
            
            try:
                # Filtra as opções com base no que foi digitado
                if search_term:
                    mask = df["TAG ATUAL"].astype(str).str.contains(str(search_term), case=False, na=False)
                    filtered_tags = df.loc[mask, "TAG ATUAL"].unique()
                else:
                    filtered_tags = df["TAG ATUAL"].unique()
                
                # Verifica se há resultados
                if len(filtered_tags) == 0:
                    st.warning("Nenhum motor encontrado com esta POSIÇÃO")
                    st.stop()
                    
                # Selecionador de TAG com as opções filtradas
                selected_tag = st.selectbox(
                    "Ou selecione a POSIÇÃO do motor:",
                    options=filtered_tags,
                    index=0
                )
                
                # Filtra os dados
                motor_data = df[df["TAG ATUAL"] == selected_tag].iloc[0]
                
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
                    **TAG Ativo:** {motor_data["TAG ATIVO"]}  
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
    pass

# Fluxo principal
check_password()
main_app()

def log_access(user_id, success, username=None):
    conn = sqlite3.connect(USER_DB)
    c = conn.cursor()
    
    ip = st.experimental_get_query_params().get('client', ['unknown'])[0]
    
    if success:
        c.execute("INSERT INTO access_logs (user_id, login_time, ip_address, success) VALUES (?, ?, ?, ?)",
                 (user_id, datetime.now(), ip, 1))
    else:
        c.execute("INSERT INTO access_logs (login_time, ip_address, success) VALUES (?, ?, ?)",
                 (datetime.now(), ip, 0))
    
    conn.commit()
    conn.close()

def log_logout(user_id):
    conn = sqlite3.connect(USER_DB)
    c = conn.cursor()
    
    # Atualiza o último registro de login com o horário de logout
    c.execute('''UPDATE access_logs SET logout_time = ?
                WHERE user_id = ? AND logout_time IS NULL
                ORDER BY login_time DESC LIMIT 1''',
             (datetime.now(), user_id))
    
    conn.commit()
    conn.close()
