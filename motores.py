# Configuração da página
# cd C:\Users\Usuário\Documents
# streamlit run motores.py
import streamlit as st
import pandas as pd
import sqlite3
import hashlib
from datetime import datetime

# Configurações
USER_DB = "users.db"
MAX_ATTEMPTS = 3

# --- Sistema de Login Multi-Usuário ---
def init_db():
    conn = sqlite3.connect(USER_DB)
    c = conn.cursor()
    
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                 username TEXT UNIQUE NOT NULL,
                 password_hash TEXT NOT NULL,
                 role TEXT NOT NULL,
                 is_active INTEGER DEFAULT 1)''')
    
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
                del st.session_state.user
                st.rerun()
        
        if st.session_state.user and st.session_state.user['role'] == 'admin':
            st.markdown("---")
            if st.toggle("Gerenciar Usuários"):
                manage_users()
                st.stop()

    # Carregar dados
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
    if not login_form():
        st.stop()
    main_app()
