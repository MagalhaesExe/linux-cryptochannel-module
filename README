# CryptoChannel - Módulo de Kernel Linux

## Autores
* **Alex Magalhães**
* **Gabriel Pereira**

## Descrição

O projeto **CryptoChannel** implementa um ecossistema completo de comunicação entre processos (IPC) mediado pelo Kernel Linux. O núcleo do projeto é um módulo de kernel (`cryptochannel_dev.ko`) que cria um dispositivo de caractere virtual em `/dev/cryptochannel`.

Diferente de *pipes* tradicionais, este canal implementa **criptografia transparente** e **políticas de segurança estritas**.

### Principais Características

* **Secure by Default:** O módulo inicia em estado "Travado" (Modo -1). Nenhuma escrita é permitida até que o administrador configure explicitamente o modo e a chave.
* **Criptografia Simétrica:** Utiliza algoritmo XOR para cifrar dados no buffer do kernel (kfifo) e decifrar na leitura.
* **Exclusão Mútua (Mutex):** Garante integridade dos dados mesmo com múltiplos produtores escrevendo simultaneamente (Race Condition Safe).
* **Protocolo de Mensagem Fixa:** Implementa comunicação baseada em pacotes de 64 bytes para sincronia perfeita em alta velocidade.
* **Monitoramento:** Estatísticas atômicas de uso expostas via `/proc`.

---

## Estrutura do Projeto

* **`cryptochannel_dev.c`**: Código fonte do Módulo de Kernel (Driver). Documentado no padrão Kernel-Doc.
* **`produtor.c`**: Cliente de espaço de usuário. Envia mensagens padronizadas (64 bytes) e trata erros de segurança (`-ENOKEY`).
* **`consumidor.c`**: Daemon de espaço de usuário. Lê continuamente o dispositivo e exibe as mensagens decifradas.
* **`teste_stress.sh`**: Script de automação para validação de concorrência e integridade.
* **`Makefile`**: Script de compilação unificado (Kernel Module + Apps de Usuário).

---

## Compilação e Instalação

O projeto conta com um `Makefile` unificado.

1.  **Compilar tudo (Módulo e Programas):**
    ```bash
    make
    ```

2.  **Carregar o módulo no Kernel:**
    ```bash
    sudo insmod cryptochannel_dev.ko
    ```

3.  **Verificar carregamento:**
    ```bash
    dmesg | tail
    ls -l /dev/cryptochannel
    ```

---

## Configuração (Obrigatória)

Por questões de segurança, o dispositivo rejeita operações de escrita (erro `ENOKEY`) logo após ser carregado. É necessário configurá-lo.

1.  **Definir permissões (opcional, para uso sem sudo):**
    ```bash
    sudo chmod 666 /dev/cryptochannel
    sudo chmod 666 /proc/cryptochannel/config
    ```

2.  **Ativar o dispositivo:**
    Envie os comandos para a interface de configuração:
    ```bash
    # Define o modo de operação (0 = XOR Padrão)
    echo "modo=0" > /proc/cryptochannel/config

    # Define a chave secreta
    echo "chave=MinhaSenhaSecreta" > /proc/cryptochannel/config
    ```

> **Nota:** Se tentar usar o `produtor` antes destes passos, ele retornará o erro: *"ERRO: Chave não configurada no kernel."*

---

## Como Usar

A forma recomendada de interagir com o driver é através dos programas desenvolvidos, que implementam o protocolo de **Padding (64 bytes)** para garantir a sincronia da criptografia.

### 1. Iniciar o Consumidor
O consumidor fica rodando em *loop* aguardando dados (bloqueante).
```bash
./consumidor
```
(Para sair, pressione Ctrl+C)

### 2. Executar o Produtor
Em outro terminal, envie mensagens:
```bash
./produtor "Ola Kernel"
./produtor "Mensagem Super Secreta"
```

---

## Teste de Estresse (Concorrência)
Para validar a exclusão mútua (Mutex) e a robustez do driver, incluímos um script de teste automatizado.

**O que o teste faz:**

1.  Configura o driver automaticamente.
2.  Inicia o Consumidor em background.
3.  Dispara múltiplos processos Produtores simultaneamente.
4.  Verifica se as mensagens chegam íntegras e sem corrupção.

**Como rodar:**
```bash
./teste_stress.sh
```
---

## Monitoramento

O módulo exporta estatísticas detalhadas de desempenho e erros.

**Para visualizar:**
```bash
cat /proc/cryptochannel/stats
```

---

## Limpeza

Para remover o módulo e limpar os binários compilados:

1.  **Remover o módulo:**
```bash
sudo rmmod cryptochannel_dev
```

2. **Limpar arquivos:**
```bash
make clean
```

