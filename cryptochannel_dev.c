/*
 * cryptochannel_dev.c
 *
 * Módulo de Kernel Linux: Dispositivo de caractere para comunicação segura.
 *
 * Autores: Alex Magalhães e Gabriel Pereira
 *
 * Descrição:
 * Este módulo implementa um dispositivo virtual (/dev/cryptochannel) que atua
 * como um canal de comunicação criptografado entre processos. Utiliza um
 * buffer circular (kfifo) para armazenamento e uma cifra XOR simples.
 * * Funcionalidades:
 * - Criptografia XOR simétrica.
 * - Leitura bloqueante (Consumer) e Escrita segura (Producer).
 * - Configuração dinâmica via /proc (Modo e Chave).
 * - Estatísticas de uso via /proc.
 * - Segurança: Inicia travado (Modo -1) até ser configurado.
 */

#include <linux/module.h>
#include <linux/init.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/kfifo.h>
#include <linux/mutex.h>
#include <linux/wait.h>
#include <linux/poll.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/atomic.h>
#include <linux/string.h>

#define DEVICE_NAME "cryptochannel"
#define PROC_DIR "cryptochannel"
#define PROC_STATS "stats"
#define PROC_CONFIG "config"

#define BUFFER_SIZE 8192        
#define KEY_MAX_LEN 64          
#define MAX_WRITE_SIZE 512      
#define READ_TIMEOUT   (30 * HZ) 

/* ===== Variáveis Globais e Estruturas ===== */

/**
 * struct cc_stats_t - Estrutura para estatísticas atômicas
 * Agrupa todos os contadores de desempenho e erro do módulo.
 */
static struct {
    atomic64_t messages;
    atomic64_t bytes_encrypted;
    atomic64_t bytes_decrypted;
    atomic64_t errors;
    atomic64_t reads_blocked;
    atomic64_t reads_timeout;
    atomic64_t reads_nonblock;
    atomic64_t writes_rejected;
    atomic64_t key_changes;
    atomic64_t invalid_ops;
} cc_stats;

static dev_t cc_dev;
static struct cdev cc_cdev;
static struct class *cc_class;

/* FIFO para armazenamento dos dados criptografados */
static DECLARE_KFIFO(cc_fifo, unsigned char, BUFFER_SIZE);

/* Mutex para proteção da chave e operações críticas */
static DEFINE_MUTEX(cc_lock);

/* Fila de espera para leitores (bloqueio na leitura) */
static DECLARE_WAIT_QUEUE_HEAD(cc_wq_read);

/* Configuração de criptografia */
static char cc_key[KEY_MAX_LEN] = {0};
static size_t cc_key_len = 0;
/* Inicia em -1 para obrigar a configuração explícita (Secure by Default) */
static int cc_mode = -1; 

/**
 * xor_cipher - Aplica cifra XOR no buffer fornecido.
 * @buf: Ponteiro para os dados a serem transformados.
 * @len: Tamanho dos dados em bytes.
 * @key: Chave de criptografia.
 * @key_len: Tamanho da chave.
 */
static void xor_cipher(unsigned char *buf, size_t len, const char *key, size_t key_len)
{
    size_t i;
    if (key_len == 0) return;

    for (i = 0; i < len; i++)
        buf[i] ^= key[i % key_len];
}

/* ===== Operações de arquivo do dispositivo ===== */

static int cc_open(struct inode *inode, struct file *filp) { return 0; }
static int cc_release(struct inode *inode, struct file *filp) { return 0; }

/**
 * cc_read - Lê dados do dispositivo (Descriptografa).
 * @filp: Ponteiro para a estrutura do arquivo.
 * @buf: Buffer do usuário para onde os dados serão copiados.
 * @count: Número de bytes solicitados.
 * @ppos: Posição atual no arquivo (ignorado para disp. de caractere).
 */
static ssize_t cc_read(struct file *filp, char __user *buf, size_t count, loff_t *ppos)
{
    unsigned int available;
    unsigned int n;
    unsigned char *kbuf;
    int ret;

    if (count == 0) return 0;

    /* Verifica modo não-bloqueante */
    if (filp->f_flags & O_NONBLOCK) {
        if (kfifo_is_empty(&cc_fifo)) {
            atomic64_inc(&cc_stats.reads_nonblock);
            return -EAGAIN;
        }   
    }

    atomic64_inc(&cc_stats.reads_blocked);

    /* Espera bloqueante com timeout e suporte a sinais */
    ret = wait_event_interruptible_timeout(
        cc_wq_read,
        !kfifo_is_empty(&cc_fifo),
        READ_TIMEOUT
    );

    if (ret == 0) { // Timeout expirou
        atomic64_inc(&cc_stats.reads_timeout);
        return -ETIMEDOUT;
    }

    if (ret < 0) // Interrompido por sinal
        return -EINTR;

    /* Processamento dos dados */
    available = kfifo_len(&cc_fifo);
    n = min(available, (unsigned int)count);

    kbuf = kmalloc(n, GFP_KERNEL);
    if (!kbuf) return -ENOMEM;

    /* Remove do FIFO (dados ainda cifrados) */
    if (kfifo_out(&cc_fifo, kbuf, n) != n) {
        atomic64_inc(&cc_stats.errors);
        kfree(kbuf);
        return -EIO;
    }

    mutex_lock(&cc_lock);
    /* Aplica descriptografia se houver chave e modo correto */
    if (cc_key_len > 0 && cc_mode == 0) {
        xor_cipher(kbuf, n, cc_key, cc_key_len);
    }
    atomic64_add(n, &cc_stats.bytes_decrypted);
    mutex_unlock(&cc_lock);
    
    if (copy_to_user(buf, kbuf, n)) {
        atomic64_inc(&cc_stats.errors);
        kfree(kbuf);
        return -EFAULT;
    }

    kfree(kbuf);
    return n;
}

/**
 * cc_write - Escreve dados no dispositivo (Criptografa).
 * @filp: Ponteiro para a estrutura do arquivo.
 * @buf: Buffer do usuário contendo os dados em claro.
 * @count: Número de bytes a escrever.
 * @ppos: Posição atual (ignorado).
 */
static ssize_t cc_write(struct file *filp, const char __user *buf, size_t count, loff_t *ppos)
{
    unsigned int avail;
    unsigned int n;
    unsigned char *kbuf;

    /* --- VALIDAÇÃO DE SEGURANÇA --- */
    mutex_lock(&cc_lock);
    if (cc_mode < 0 || cc_key_len == 0) {
        mutex_unlock(&cc_lock);
        return -ENOKEY; /* Requer configuração prévia */
    }
    mutex_unlock(&cc_lock);

    if (count > MAX_WRITE_SIZE) {
        atomic64_inc(&cc_stats.writes_rejected);
        return -EINVAL;
    }

    if (count == 0) return 0;

    avail = kfifo_avail(&cc_fifo);
    if (avail == 0) return -ENOSPC; /* Buffer cheio */

    n = min(avail, (unsigned int)count);

    kbuf = kmalloc(n, GFP_KERNEL);
    if (!kbuf) return -ENOMEM;

    if (copy_from_user(kbuf, buf, n)) {
        atomic64_inc(&cc_stats.errors);
        kfree(kbuf);
        return -EFAULT;
    }

    mutex_lock(&cc_lock);
    /* Criptografa antes de armazenar */
    if (cc_mode == 0)
        xor_cipher(kbuf, n, cc_key, cc_key_len);
    
    atomic64_add(n, &cc_stats.bytes_encrypted);
    atomic64_inc(&cc_stats.messages);
    mutex_unlock(&cc_lock);

    /* Insere no FIFO */
    if (kfifo_in(&cc_fifo, kbuf, n) != n) {
        atomic64_inc(&cc_stats.errors);
        kfree(kbuf);
        return -EIO;
    }

    kfree(kbuf);

    /* Notifica leitores */
    wake_up_interruptible(&cc_wq_read);
    return n;
}

static unsigned int cc_poll(struct file *filp, poll_table *wait)
{
    poll_wait(filp, &cc_wq_read, wait);
    if (!kfifo_is_empty(&cc_fifo))
        return POLLIN | POLLRDNORM;
    return 0;
}

static const struct file_operations cc_fops = {
    .owner = THIS_MODULE,
    .open  = cc_open,
    .release = cc_release,
    .read  = cc_read,
    .write = cc_write,
    .poll  = cc_poll,
};

/* ===== Interface /proc ===== */

static int proc_stats_show(struct seq_file *m, void *v)
{
    seq_printf(m, "Mensagens_trocadas: %lld\n", atomic64_read(&cc_stats.messages));
    seq_printf(m, "Bytes_criptografados: %lld\n", atomic64_read(&cc_stats.bytes_encrypted));
    seq_printf(m, "Bytes_descriptografados: %lld\n", atomic64_read(&cc_stats.bytes_decrypted));
    seq_printf(m, "Modo: %d\n", cc_mode);
    seq_printf(m, "Tamanho_chave: %zu\n", cc_key_len);
    seq_printf(m, "Tentativas_de_Leitura: %lld\n", atomic64_read(&cc_stats.reads_blocked));
    seq_printf(m, "Leituras_timeout: %lld\n", atomic64_read(&cc_stats.reads_timeout));
    seq_printf(m, "Leituras_sem_dados: %lld\n", atomic64_read(&cc_stats.reads_nonblock));
    seq_printf(m, "Escritas_rejeitadas: %lld\n", atomic64_read(&cc_stats.writes_rejected));
    seq_printf(m, "Mudancas_de_chave: %lld\n", atomic64_read(&cc_stats.key_changes));
    seq_printf(m, "Tentativas_invalidas: %lld\n", atomic64_read(&cc_stats.invalid_ops));
    seq_printf(m, "Erros: %lld\n", atomic64_read(&cc_stats.errors));
    return 0;
}

static int proc_stats_open(struct inode *inode, struct file *file)
{
    return single_open(file, proc_stats_show, NULL);
}

static const struct proc_ops proc_stats_ops = {
    .proc_open    = proc_stats_open,
    .proc_read    = seq_read,
    .proc_lseek   = seq_lseek,
    .proc_release = single_release,
};

static ssize_t proc_config_read(struct file *file, char __user *buf, size_t count, loff_t *ppos)
{
    char temp[256];
    size_t len;

    mutex_lock(&cc_lock);
    len = scnprintf(temp, sizeof(temp), "modo=%d\nchave=%s\n", cc_mode, cc_key);
    mutex_unlock(&cc_lock);

    return simple_read_from_buffer(buf, count, ppos, temp, len);
}

static ssize_t proc_config_write(struct file *file, const char __user *buf, size_t count, loff_t *ppos)
{
    char kbuf[256];
    size_t n;

    n = min(count, sizeof(kbuf) - 1);
    if (copy_from_user(kbuf, buf, n)) return -EFAULT;
    kbuf[n] = '\0';

    /* Remove quebra de linha final se existir */
    if (n > 0 && kbuf[n-1] == '\n')
        kbuf[n-1] = '\0';

    mutex_lock(&cc_lock);

    /* --- Configuração de MODO --- */
    if (strncmp(kbuf, "modo=", 5) == 0) {
        int new_mode;
        if (kstrtoint(kbuf + 5, 10, &new_mode) || new_mode != 0) {
            atomic64_inc(&cc_stats.invalid_ops);
            mutex_unlock(&cc_lock);
            return -EINVAL;
        }
        cc_mode = new_mode;

    /* --- Configuração de CHAVE --- */
    } else if (strncmp(kbuf, "chave=", 6) == 0) {
        /* Declaração local para evitar warning de unused variable em outros blocos */
        char *new_val_ptr = kbuf + 6;
        size_t new_len = strlen(new_val_ptr);

        if (!kfifo_is_empty(&cc_fifo)) {
            atomic64_inc(&cc_stats.invalid_ops);
            mutex_unlock(&cc_lock);
            return -EBUSY;
        }

        /* CORREÇÃO: Valida tamanho ANTES de alterar a chave global */
        if (new_len == 0) {
            atomic64_inc(&cc_stats.invalid_ops);
            mutex_unlock(&cc_lock);
            return -EINVAL; /* Chave vazia rejeitada */
        }

        strncpy(cc_key, new_val_ptr, KEY_MAX_LEN - 1);
        cc_key[KEY_MAX_LEN - 1] = '\0';
        cc_key_len = strnlen(cc_key, KEY_MAX_LEN - 1);
        
        atomic64_inc(&cc_stats.key_changes);

    } else {
        atomic64_inc(&cc_stats.invalid_ops);
        mutex_unlock(&cc_lock);
        return -EINVAL;
    }

    mutex_unlock(&cc_lock);
    return count;
}

static const struct proc_ops proc_config_ops = {
    .proc_read  = proc_config_read,
    .proc_write = proc_config_write,
};

/* ===== Init & Exit ===== */
static struct proc_dir_entry *proc_dir;

static int __init cc_init(void)
{
    int ret;
    struct device *dev;

    pr_info("cryptochannel: iniciando carregamento do modulo\n");

    ret = alloc_chrdev_region(&cc_dev, 0, 1, DEVICE_NAME);
    if (ret) return ret;

    cdev_init(&cc_cdev, &cc_fops);
    cc_cdev.owner = THIS_MODULE;
    ret = cdev_add(&cc_cdev, cc_dev, 1);
    if (ret) goto err_unregister;

    cc_class = class_create(DEVICE_NAME);
    if (IS_ERR(cc_class)) {
        ret = PTR_ERR(cc_class);
        goto err_cdev;
    }
    dev = device_create(cc_class, NULL, cc_dev, NULL, DEVICE_NAME);
    if (IS_ERR(dev)) {
        ret = PTR_ERR(dev);
        goto err_class;
    }

    INIT_KFIFO(cc_fifo);
    /* Zera todas as estatísticas na inicialização */
    memset(&cc_stats, 0, sizeof(cc_stats));

    proc_dir = proc_mkdir(PROC_DIR, NULL);
    if (!proc_dir) {
        ret = -ENOMEM;
        goto err_device;
    }

    if (!proc_create(PROC_STATS, 0444, proc_dir, &proc_stats_ops)) {
        ret = -ENOMEM;
        goto err_proc;
    }
    if (!proc_create(PROC_CONFIG, 0666, proc_dir, &proc_config_ops)) {
        ret = -ENOMEM;
        goto err_proc;
    }

    pr_info("cryptochannel: carregado com sucesso\n");
    return 0;

err_proc:
    remove_proc_entry(PROC_STATS, proc_dir);
    remove_proc_entry(PROC_CONFIG, proc_dir);
    remove_proc_entry(PROC_DIR, NULL);
err_device:
    device_destroy(cc_class, cc_dev);
err_class:
    class_destroy(cc_class);
err_cdev:
    cdev_del(&cc_cdev);
err_unregister:
    unregister_chrdev_region(cc_dev, 1);
    return ret;
}

static void __exit cc_exit(void)
{
    remove_proc_entry(PROC_STATS, proc_dir);
    remove_proc_entry(PROC_CONFIG, proc_dir);
    remove_proc_entry(PROC_DIR, NULL);

    device_destroy(cc_class, cc_dev);
    class_destroy(cc_class);
    cdev_del(&cc_cdev);
    unregister_chrdev_region(cc_dev, 1);

    pr_info("cryptochannel: modulo descarregado\n");
}

module_init(cc_init);
module_exit(cc_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Alex Magalhães e Gabriel Pereira");
MODULE_DESCRIPTION("Dispositivo criptografado com suporte a configuracao segura");
MODULE_VERSION("1.2");