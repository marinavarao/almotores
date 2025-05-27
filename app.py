# app.py
from database import init_db, restore_from_json
from auth import authenticate
import streamlit as st
import pandas as pd
import sqlite3
import hashlib
from datetime import datetime, timedelta  # Importação corrigida
import uuid
import os

def main():
    # Inicialização
    init_db()
    restore_from_json()  # Restaura dados ao iniciar
    
    # Verificação de sessão
    if 'user' not in st.session_state:
        st.session_state.user = None
    
    if not st.session_state.user:
        check_persisted_session()  # Verifica sessões salvas
    
    # ... resto do seu código ...
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
                return pd.read_excel("motores.xlsx")
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

def check_persisted_session():
    """Verifica sessões no banco de dados"""
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    
    # Sessões válidas (últimas 8h)
    c.execute("""
    SELECT user_id, session_id FROM sessions
    WHERE last_activity > ?
    """, (datetime.now() - timedelta(hours=8),))
    
    session = c.fetchone()
    conn.close()
    
    if session:
        user_id, session_id = session
        conn = sqlite3.connect(DB_PATH)
        c = conn.cursor()
        c.execute("SELECT username, role FROM users WHERE id = ?", (user_id,))
        user_data = c.fetchone()
        conn.close()
        
        if user_data:
            st.session_state.user = {
                "id": user_id,
                "username": user_data[0],
                "role": user_data[1],
                "session_id": session_id
            }
            update_session_activity(session_id)  # Atualiza timestamp
