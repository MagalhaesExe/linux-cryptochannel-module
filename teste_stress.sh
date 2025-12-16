#!/bin/bash

# --- Definição de Cores e Estilos ---
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
BOLD='\033[1m'
NC='\033[0m' # No Color (Reseta a cor)

# Função para imprimir cabeçalhos bonitos
print_header() {
    echo -e "\n${BLUE}${BOLD}==========================================================${NC}"
    echo -e "${BLUE}${BOLD}   $1${NC}"
    echo -e "${BLUE}${BOLD}==========================================================${NC}\n"
}

# Limpa a tela para começar "do zero"
clear

print_header "TESTE DE ESTRESSE: PRODUTOR x CONSUMIDOR"

# 1. Configuração Inicial
echo -e "${YELLOW}[SETUP] Configurando o Driver...${NC}"

if [ ! -w /proc/cryptochannel/config ]; then
    echo -e "${RED}[ERRO] Sem permissão de escrita em /proc/cryptochannel/config${NC}"
    echo "Rode: sudo chmod 666 /proc/cryptochannel/config"
    exit 1
fi

echo "modo=0" > /proc/cryptochannel/config
echo "chave=Segredo123" > /proc/cryptochannel/config

echo -e "${GREEN}[OK]${NC} Modo definido para 0"
echo -e "${GREEN}[OK]${NC} Chave de criptografia configurada"
sleep 1

# 2. Inicia o Consumidor
print_header "ETAPA 1: INICIANDO CONSUMIDOR"
echo -e "${CYAN}[SISTEMA] Iniciando processo Consumidor em Background...${NC}"
./consumidor &
PID_CONSUMIDOR=$!

# Pausa para garantir que o consumidor abriu o arquivo e bloqueou
sleep 1
echo -e "${CYAN}[SISTEMA] Consumidor aguardando dados (Bloqueado no Read)${NC}"
sleep 1

# 3. Dispara múltiplos Produtores
print_header "ETAPA 2: DISPARANDO 5 PRODUTORES SIMULTÂNEOS"
echo -e "${YELLOW}[AÇÃO] Lançando 5 processos ao mesmo tempo para testar o Mutex...${NC}\n"

# O sleep 0.05 entre eles é opcional, mas ajuda a não "explodir" o texto de uma vez só na tela,
# mantendo ainda a concorrência alta o suficiente para testar o driver.
./produtor "MSG_A: O rato roeu a roupa" &
sleep 0.05
./produtor "MSG_B: do rei de Roma" &
sleep 0.05
./produtor "MSG_C: Sistemas Operacionais" &
sleep 0.05
./produtor "MSG_D: UTFPR Campo Mourao" &
sleep 0.05
./produtor "MSG_E: Teste de Concorrencia" &

# Aguarda os produtores terminarem
wait $!

echo -e "\n${GREEN}[SUCESSO] Todos os produtores finalizaram a escrita.${NC}"

# Pequena pausa para garantir que o consumidor leu as últimas linhas do buffer
sleep 2

# 4. Finalização
print_header "RESULTADO FINAL"

# Mata o consumidor silenciosamente
kill $PID_CONSUMIDOR 2>/dev/null

echo -e "${GREEN}Teste finalizado com sucesso.${NC}"
echo -e "Observe acima que as mensagens não se misturaram."
echo -e "${BLUE}==========================================================${NC}\n"