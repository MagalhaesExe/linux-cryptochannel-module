/*
 * consumidor.c - Versão com Loop de Leitura (Daemon)
 * Autores: Alex Magalhães e Gabriel Pereira
 */
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <signal.h>

#define DEVICE_PATH "/dev/cryptochannel"
#define READ_BUF_SIZE 1024

static volatile int keep_running = 1;

/* Tratamento para fechar o arquivo ao receber Ctrl+C */
void handle_sigint(int sig) {
    keep_running = 0;
}

int main() {
    int fd;
    ssize_t ret;
    char buffer[READ_BUF_SIZE];

    signal(SIGINT, handle_sigint);

    printf("[Consumidor] Abrindo dispositivo para leitura contínua...\n");
    fd = open(DEVICE_PATH, O_RDONLY);
    if (fd < 0) {
        perror("[Consumidor] Falha ao abrir o dispositivo");
        return errno;
    }

    printf("[Consumidor] Monitorando mensagens... (Pressione Ctrl+C para sair)\n");

    while (keep_running) {
        // Limpa buffer
        memset(buffer, 0, READ_BUF_SIZE);

        // Bloqueia aqui até chegar dados
        ret = read(fd, buffer, READ_BUF_SIZE - 1);

        if (ret < 0) {
            if (errno == EINTR) {
                break; // Interrompido por sinal (Ctrl+C), sai do loop
            } else if (errno == EAGAIN) {
                continue; // Tenta de novo (se fosse non-block)
            } else {
                perror("[Consumidor] Erro na leitura");
                break;
            }
        } else if (ret == 0) {
            // EOF ou nada lido, continua tentando
            continue;
        } else {
            buffer[ret] = '\0';
            printf("[Consumidor Recebeu]: %s\n", buffer);
        }
    }

    printf("\n[Consumidor] Encerrando...\n");
    close(fd);
    return 0;
}