#include <errno.h>
#include <unistd.h>
#include <malloc.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <resolv.h>
#include "openssl/ssl.h"
#include "openssl/err.h"
#include "openssl/bio.h"
 
#define FAIL    -1
#define MAXBUF 1024

typedef enum {false, true} bool;
bool udp = false;
bool is_v6 = false;
char *file;

typedef struct {
    SSL_CTX *ctx;
    SSL *ssl;
    BIO *bio;
} DTLSParams;


//Initialize DTLS context 
int dtls_InitCtx(DTLSParams* params, const char* keyname){
    int result = 0;

    OpenSSL_add_all_algorithms();

    //create a new DTLS context
    params->ctx = SSL_CTX_new(DTLSv1_method());
    if (params->ctx == NULL){
        printf("ERROR: cannot create SSL_CTX.\n");
        ERR_print_errors_fp(stderr);
        return -1;
    }
    
    //Set our supported ciphers
    result = SSL_CTX_set_cipher_list(params->ctx,"ALL:!ADH:!LOW:!EXP:!MD5:@STRENGTH");
    if(result != 1){
        printf("ERROR: cannot set the cipher list.\n");
        ERR_print_errors_fp(stderr);
        return -2;
    }

    //The client doesn't have to send its certificate
    SSL_CTX_set_verify(params->ctx, SSL_VERIFY_PEER, NULL);
    SSL_CTX_set_verify_depth(params->ctx, 1);

    //Load key and certificate
    char cert[1024];
    char key[1024];
    sprintf(cert, "./%s-cert.pem", keyname);
    sprintf(key, "./%s-key.pem", keyname);

    //Load the certificate file; contains the public key
    result = SSL_CTX_use_certificate_file(params->ctx, cert, SSL_FILETYPE_PEM);
    if (result != 1){
        printf("ERROR:cannot load certificate file.\n");
        ERR_print_errors_fp(stderr);
        return -3;
    }

    //Load private key
    result = SSL_CTX_use_PrivateKey_file(params->ctx, key, SSL_FILETYPE_PEM);
    if (result != 1){
        printf("ERROR: cannot load private key file.\n");
        ERR_print_errors_fp(stderr);
        return -4;
    }

    //Check if private key is valid
    result = SSL_CTX_check_private_key(params->ctx);
    if (result != 1){
        printf("ERROR: checking the private key failed.\n");
        ERR_print_errors_fp(stderr);
        return -5;
    }
    return 0;
}

//DTLS Initialize Client
int dtls_InitClient(DTLSParams* params, const char *address){
    params->bio = BIO_new_ssl_connect(params->ctx);
    if (params->bio == NULL) {
        fprintf(stderr, "error connecting to server\n");
        return -1;
    }

    BIO_set_conn_hostname(params->bio, address);
    BIO_get_ssl(params->bio, &(params->ssl));
    if (params->ssl == NULL) {
        fprintf(stderr, "error, exit\n");
        return -1;
    }

    SSL_set_connect_state(params->ssl);
    SSL_set_mode(params->ssl, SSL_MODE_AUTO_RETRY);

    return 0;
}

void DTLSClient(char *address, const char *file){
    DTLSParams client;
    
    // Initialize the DTLS context from the keystore and then create the server
    // SSL state.
    if (dtls_InitCtx(&client, "client") < 0) {
        exit(EXIT_FAILURE);
    }
    if (dtls_InitClient(&client, address) < 0) {
        exit(EXIT_FAILURE);
    }

    // Attempt to connect to the server and complete the handshake.
    int result = SSL_connect(client.ssl);
    if (result != 1) {
        perror("Unable to connect to the DTLS server.\n");
        exit(EXIT_FAILURE);
    }

    // Read the contents of the file (up to 4KB) into a buffer
    FILE *fp = fopen(file, "rb");
    uint8_t buffer[4096] = { 0 };
    size_t numRead = fread(buffer, 1, 4096, fp);

    // Write the buffer to the server
    int written = SSL_write(client.ssl, buffer, numRead);
    if (written != numRead) {
        perror("Failed to write the entire buffer.\n");
        exit(EXIT_FAILURE);
    }

    int read = -1;
    do {
        // Read the output from the server. If it's not empty, print it.
        read = SSL_read(client.ssl, buffer, sizeof(buffer));
        if (read > 0) {
            printf("IN[%d]: ", read);
            int i;
            for (i = 0; i < read; i++) {
                printf("%c", buffer[i]);
            }
            printf("\n");
        }
    } 
    while (read < 0);

    //Shutdown DTLS
    SSL_shutdown(client.ssl);
    SSL_free(client.ssl);
    //close(client);
}

static void show_help(int argc, char *argv[]){
    printf("Usage:\n");
    printf("  %s <ip:address> -f <file_path> [-u] [-h]\n", argv[0]);
    printf("Options:\n");
    printf("  -f <file_path>  queue file to send. Required\n");
    printf("  -h              show help\n");
    printf("  -u              connect to a UDP port\n");
}

int main(int argc, char *argv[]){
    int opt;
    char *address = NULL;
    const char file;

    if (argc < 2){
        show_help(argc, argv);
        exit(1);
    }
    address = argv[1];

    while ((opt = getopt(argc, argv, "huf:")) != -1) {
        switch (opt) {
        case 'u':
            udp = true;
            break;
        case 'h':
            show_help(argc, argv);
            exit(0);
            break;
        case 'f':
            file = optarg;
            break;
        }
    }
    
    //Initialize SSL
    SSL_library_init();
    
    if (udp == true){
        DTLSClient(address, file);
    }
    

}