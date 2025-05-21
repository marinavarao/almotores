# Configuração da página
# cd C:\Users\Usuário\Documents
# streamlit run motores.py
import streamlit as st
import pandas as pd
from datetime import datetime

# Configurações de segurança
PASSWORD = "mane2025"  # Troque por uma senha complexa
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

def main_app():
    st.set_page_config(
        page_title="Catálogo de Motores - Busca por TAG",
        layout="wide",
    )

    @st.cache_data
    def load_data():
        try:
            df = pd.read_excel("motores.xlsx")
            
            # Verifica se as colunas necessárias existem
            required_columns = ['TAG ATIVO', 'TAG ATUAL', 'DESCRIÇÃO', 'LOCAL', 'FABRICANTE', 'MODELO']
            missing_columns = [col for col in required_columns if col not in df.columns]
            
            if missing_columns:
                st.error(f"Colunas obrigatórias não encontradas: {', '.join(missing_columns)}")
                return pd.DataFrame()
                
            return df
        except Exception as e:
            st.error(f"Erro ao carregar dados: {str(e)}")
            return pd.DataFrame()

    # Carrega os dados
    df = load_data()

    if not df.empty:
        # Debug: Mostrar colunas disponíveis (opcional)
        # st.write("Colunas disponíveis:", df.columns.tolist())
        
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
            
            # Filtra os dados com tratamento seguro
            try:
                motor_data = df[df["TAG ATIVO"] == selected_tag].iloc[0].to_dict()
            except IndexError:
                st.error("Nenhum dado encontrado para a TAG selecionada")
                st.stop()
            
        except Exception as e: 
            st.error(f"Erro ao filtrar dados: {str(e)}")
            st.stop()
        
        # --- EXIBIÇÃO DOS DADOS ---
        st.markdown("---")
        st.subheader(f"Dados Técnicos - {selected_tag}")
        
        # Função segura para mostrar dados
        def safe_get(data, key, default="N/A"):
            return data.get(key, default)
        
        # Organização em abas
        tab1, tab2, tab3 = st.tabs(["Informações Básicas", "Especificações Técnicas", "Detalhes Mecânicos"])
        
        with tab1:
            col1, col2 = st.columns(2)
            with col1:
                st.markdown(f"""
                **TAG Atual:** {safe_get(motor_data, 'TAG ATUAL')}  
                **Descrição:** {safe_get(motor_data, 'DESCRIÇÃO')}  
                **Localização:** {safe_get(motor_data, 'LOCAL')}  
                **Área de Instalação:** {safe_get(motor_data, 'ÁREA')}  
                """)
            with col2:
                st.markdown(f"""
                **Fabricante:** {safe_get(motor_data, 'FABRICANTE')}  
                **Modelo:** {safe_get(motor_data, 'MODELO')}  
                **N° Série:** {safe_get(motor_data, 'N° DE SÉRIE')}  
                **Ano Fabricação:** {safe_get(motor_data, 'ANO FAB.')}  
                """)
        
        with tab2:
            col1, col2 = st.columns(2)
            with col1:
                st.markdown(f"""
                **Potência:** {safe_get(motor_data, 'POTÊNCIA (kW)')} kW  
                **Tensão:** {safe_get(motor_data, 'TENSÃO (V)')} V  
                **Corrente:** {safe_get(motor_data, 'CORRENTE(A)')} A  
                **Frequência:** {safe_get(motor_data, 'FREQ.(Hz)')} Hz  
                """)
            with col2:
                st.markdown(f"""
                **N° Fases:** {safe_get(motor_data, 'Nº DE FASES')}  
                **N° Polos:** {safe_get(motor_data, 'N° POLOS')}  
                **RPM:** {safe_get(motor_data, 'RPM')}  
                **Grau IP:** {safe_get(motor_data, 'GRAU IP')}  
                """)
        
        with tab3:
            col1, col2 = st.columns(2)
            with col1:
                st.markdown(f"""
                **Carcaça:** {safe_get(motor_data, 'CARCAÇA')}  
                **Peso:** {safe_get(motor_data, 'PESO (kg)')} kg  
                **Posição Instalação:** {safe_get(motor_data, 'POSIÇÃO DE INSTALAÇÃO')}  
                """)
            with col2:
                st.markdown(f"""
                **Rolamento Dianteiro:** {safe_get(motor_data, 'ROLAMENTO DIANTEIRO')}  
                **Rolamento Traseiro:** {safe_get(motor_data, 'ROLAMENTO TRASEIRO')}  
                **Tipo Graxa:** {safe_get(motor_data, 'GRAXA TIPO')}  
                """)
        
        # Botão para mostrar todos os dados (opcional)
        if st.button("Mostrar todos os dados brutos"):
            st.write(motor_data)

    else:
        st.warning("Nenhum dado foi carregado. Verifique o arquivo de origem.")

    # Rodapé
    st.markdown("---")
    st.caption("Sistema de Catálogo de Motores - © 2025")

# Fluxo principal
check_password()
main_app()
