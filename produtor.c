/*
 * produtor.c - Envia mensagens para o dispositivo cryptochannel
 * Autores: Alex Magalhães e Gabriel Pereira
 */
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

#define DEVICE_PATH "/dev/cryptochannel"

int main(int argc, char *argv[]) {
    int fd;
    ssize_t ret;
    char *mensagem;

    if (argc < 2) {
        printf("Uso: %s <mensagem>\n", argv[0]);
        return 1;
    }

    mensagem = argv[1];

    printf("[Produtor] Tentando abrir o dispositivo %s...\n", DEVICE_PATH);
    fd = open(DEVICE_PATH, O_WRONLY); // Abre apenas para escrita
    if (fd < 0) {
        perror("[Produtor] Falha ao abrir o dispositivo");
        return errno;
    }

    printf("[Produtor] Escrevendo mensagem: '%s' (%lu bytes)\n", mensagem, strlen(mensagem));
    
    // Tenta escrever no dispositivo
    ret = write(fd, mensagem, strlen(mensagem));

    if (ret < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
             fprintf(stderr, "[Produtor] O buffer está cheio.\n");
        } 
        else if (errno == ENOKEY) {
             fprintf(stderr, "[Produtor] ERRO: Dispositivo não configurado!\n");
             fprintf(stderr, "   É necessário definir o MODO e a CHAVE antes de usar:\n");
             fprintf(stderr, "   1. echo 'modo=0' > /proc/cryptochannel/config\n");
             fprintf(stderr, "   2. echo 'chave=SUA_SENHA' > /proc/cryptochannel/config\n");
        }
        else {
             perror("[Produtor] Falha na escrita");
        }
    } else {
        printf("[Produtor] Sucesso! %zd bytes escritos.\n", ret);
    }

    close(fd);
    return 0;
}