# Nome do módulo (sem a extensão .ko)
MODULE_NAME := cryptochannel_dev

# Arquivos de objeto para o kernel
obj-m := $(MODULE_NAME).o

# Variáveis para compilação de usuário
CC = gcc
CFLAGS = -Wall -g

# Diretório de build do kernel atual
KERNEL_DIR = /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)

# Target padrão (executado quando você roda apenas 'make')
all: module produtor consumidor

# 1. Compilação do Módulo de Kernel
module:
	@echo "--- Compilando Modulo Kernel ---"
	$(MAKE) -C $(KERNEL_DIR) M=$(PWD) modules

# 2. Compilação do Produtor
produtor: produtor.c
	@echo "--- Compilando Produtor ---"
	$(CC) $(CFLAGS) produtor.c -o produtor

# 3. Compilação do Consumidor
consumidor: consumidor.c
	@echo "--- Compilando Consumidor ---"
	$(CC) $(CFLAGS) consumidor.c -o consumidor

# Limpeza dos arquivos gerados (kernel e usuário)
clean:
	@echo "--- Limpando arquivos ---"
	$(MAKE) -C $(KERNEL_DIR) M=$(PWD) clean
	rm -f produtor consumidor