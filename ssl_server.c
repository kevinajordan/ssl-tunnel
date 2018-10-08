#include <errno.h>
#include <unistd.h>
#include <malloc.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <resolv.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/crypto.h>

 
#define FAIL    -1
#define MAXBUFF 1024

typedef enum {false, true} bool;
bool udp = false;
bool is_v6 = false;
char *file;

typedef struct {
    SSL_CTX *ctx;
    SSL *ssl;
    BIO *bio;
} DTLSParams;

//Structure to hold mutex
struct CRYPTO_dynlock_value{
    pthread_mutex_t mutex;
};

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

//DTLS Initialize Server
int dtls_InitServer(DTLSParams* params){
    params->bio = BIO_new_ssl_connect(params->ctx);
    if (params->bio == NULL){
        fprintf(stderr, "ERROR: connecting with BIOs\n");
        return -1;
    }

    BIO_get_ssl(params->bio, &(params->ssl));
    if (params->ssl == NULL){
        fprintf(stderr, "ERROR: failed to get ssl\n");
        return -1;
    }

    SSL_set_accept_state(params->ssl);
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

/*
void* SendFile(int *arg){
    int connfd = (int)*arg;
    printf("Connection accepted and id: %d\n",connfd);
    write(connfd, fname, 256);
    FILE *fp = fopen(fname, "rb");
    if(fp==NULL){
        printf("ERROR:File open failed\n");
        return 1;
    }
    //read data from file and send it
    while(1){
        unsigned char buff[1024]={0};
        int nread = fread(buff,1,1024,fp);

        //if read was successful, send data
        if(nread > 0){
            if(feof(fp)){
                printf("End of file\n");
                printf("File transfer completed for id: %d\n",connfd);
            }
            if(ferror(fp))
                printf("ERROR: reading\n");
                break;
        }
    }
    printf("Closing connection for id: %d\n",connfd);
    close(connfd);
    shutdown(connfd, SHUT_WR);
    sleep(2);
}
*/

int OpenListener(int port)
{   int sd;
    char buf[MAXBUFF];
    struct sockaddr_in addr;
    
    //Create UDP socket if UDP option is set.
    if (udp == true){
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);
        addr.sin_addr.s_addr = htonl(INADDR_ANY);
    
        sd = socket(AF_INET, SOCK_DGRAM, 0);
        if (sd < 0) {
            perror("ERROR:Unable to create UDP socket");
            exit(EXIT_FAILURE);
        }
    
        if (bind(sd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
            perror("ERROR: Unable to bind UDP socket");
            exit(EXIT_FAILURE);
        }
        else{
            printf("Successfully bound UDP %d\n", port);
        }
    
        return sd;
    }
    
    //IPv6 Socket Creation
    else if (is_v6==true){
        if((sd = socket(AF_INET6, SOCK_STREAM, 0))== -1){
            perror("ERROR: IPv6 socket creation failed\n");
            abort();
        }
        bzero(&addr, sizeof(addr));
        addr.sin_family = AF_INET6;
        addr.sin_port = htons(port);
        addr.sin_addr.s_addr = INADDR_ANY;
        if (bind(sd, (struct sockaddr *)&addr, sizeof(addr))< 0 ){
            perror("ERROR: IPv6 socket bind failed\n");
            abort();
        }
        if ( listen(sd, 10) != 0 )
        {
            perror("Can't configure listening port");
            abort();
        }
        return sd; 
    }

    //Normal IPv4 TCP Listener
    else{
        sd = socket(AF_INET, SOCK_STREAM, 0);
        bzero(&addr, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_port = htons(port);
        addr.sin_addr.s_addr = INADDR_ANY;
        if ( bind(sd, (struct sockaddr*)&addr, sizeof(addr)) != 0 )
        {
            perror("can't bind port");
            abort();
        }
        if ( listen(sd, 10) != 0 )
        {
            perror("Can't configure listening port");
            abort();
        }
        return sd;
    }
}
 
int isRoot()
{
    if (getuid() != 0)
    {
        return 0;
    }
    else
    {
        return 1;
    }
 
}

SSL_CTX* InitServerCTX(void)
{   SSL_METHOD *method;
    SSL_CTX *ctx;
 
    OpenSSL_add_all_algorithms();  /* load & register all cryptos, etc. */
    SSL_load_error_strings();   /* load all error messages */
    method = TLSv1_2_server_method();  /* create new server-method instance */
    ctx = SSL_CTX_new(method);   /* create new context from method */
    if ( ctx == NULL )
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
    return ctx;
}
 
void LoadCertificates(SSL_CTX* ctx, char* CertFile, char* KeyFile)
{
    /* set the local certificate from CertFile */
    if ( SSL_CTX_use_certificate_file(ctx, CertFile, SSL_FILETYPE_PEM) <= 0 )
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
    /* set the private key from KeyFile (may be the same as CertFile) */
    if ( SSL_CTX_use_PrivateKey_file(ctx, KeyFile, SSL_FILETYPE_PEM) <= 0 )
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
    /* verify private key */
    if ( !SSL_CTX_check_private_key(ctx) )
    {
        fprintf(stderr, "Private key does not match the public certificate\n");
        abort();
    }
}
 
void ShowCerts(SSL* ssl)
{   X509 *cert;
    char *line;
 
    cert = SSL_get_peer_certificate(ssl); /* Get certificates (if available) */
    if ( cert != NULL )
    {
        printf("Server certificates:\n");
        line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
        printf("Subject: %s\n", line);
        free(line);
        line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
        printf("Issuer: %s\n", line);
        free(line);
        X509_free(cert);
    }
    else
        printf("No certificates.\n");
}
 
void Servlet(SSL* ssl) /* Serve the connection -- threadable */
{   char buf[1024];
    char reply[1024];
    int sd, bytes;
    const char* HTMLecho="<html><body><pre>%s</pre></body></html>\n\n";
 
    if ( SSL_accept(ssl) == FAIL )     /* do SSL-protocol accept */
        ERR_print_errors_fp(stderr);
    else
    {
        ShowCerts(ssl);        /* get any certificates */
        bytes = SSL_read(ssl, buf, sizeof(buf)); /* get request */
        if ( bytes > 0 )
        {
            buf[bytes] = 0;
            printf("Client msg: \"%s\"\n", buf);
            sprintf(reply, HTMLecho, buf);   /* construct reply */
            SSL_write(ssl, reply, strlen(reply)); /* send reply */
        }
        else
            ERR_print_errors_fp(stderr);
    }
    sd = SSL_get_fd(ssl);       /* get socket connection */
    SSL_shutdown(ssl);
    SSL_free(ssl);         /* release SSL state */
    close(sd);          /* close connection */
}

void DTLSServer(int port){
    int sock_fd = OpenListener(port);
    DTLSParams server;

    // Initialize the DTLS context from the keystore and then create the server
    // SSL state.
    if (dtls_InitCtx(&server, "server") < 0) {
        exit(EXIT_FAILURE);
    }
    if (dtls_InitServer(&server) < 0) {
        exit(EXIT_FAILURE);
    }
    
    // Loop forever accepting messages from the client, printing their messages,
    // and then terminating their connections
    char outbuf[4096];
    while(true) {
        struct sockaddr_in addr;
        uint len = sizeof(addr);
        SSL *ssl;
    
        // Receive an incoming UDP packet (connection)
        int client = recvfrom(sock_fd,outbuf, sizeof(outbuf),0, (struct sockaddr*) &addr, &len);
        if (client < 0) {
            perror("ERROR: Unable to accept\n");
            exit(EXIT_FAILURE);
        }
    
        // Set the SSL descriptor to that of the client socket
        SSL_set_fd(server.ssl, client);
    
        // Attempt to complete the DTLS handshake
        // If successful, the DTLS link state is initialized internally
        if (SSL_accept(server.ssl) <= 0) {
            ERR_print_errors_fp(stderr);
        } else {
            // Read from the DTLS link
            int read = SSL_read(server.ssl, outbuf, sizeof(outbuf));
    
            // Print out the client's message
            if (read > 0) {
                printf("IN[%d]: ", read);
                int i;
                for (i = 0; i < read; i++) {
                    printf("%c", outbuf[i]);
                }
                printf("\n");
    
                // Echo the message back to the client
                SSL_write(server.ssl, outbuf, sizeof(outbuf));
            }
        }
    
        // When done reading the single message, close the client's connection
        // and continue waiting for another.
        close(client);
    }
}

/*Callback functions for creation, deletion, and modification of mutexes
static struct CRYPTO_dynlock_value * dyn_create_func (const char *, int);
static void dyn_destroy_func (struct CRYPTO_dynlock_value *, const char *, int);
static void dyn_lock_func (struct CRYPTO_dynlock_value *, const char *, int);
*/

//Creation function
static struct CRYPTO_dynlock_value *dyn_create_func(const char *file, int line){
    struct CRYPTO_dynlock_value *value;
    value = (struct CRYPTO_dynlock_value *) malloc(sizeof(struct CRYPTO_dynlock_value));
    pthread_mutex_init(&value->mutex, NULL);
    return value;
}

//Destory Function
static void dyn_destroy_func(struct CRYPTO_dynlock_value *l, const char *file, int line){
    pthread_mutex_destroy(&l->mutex);
    free(l);
}

//Modification function
static void dyn_lock_func(int mode, struct CRYPTO_dynlock_value *l, const char *file, int line){
    if(mode & CRYPTO_LOCK)
        pthread_mutex_lock(&l->mutex);
    else    
        pthread_mutex_unlock(&l->mutex);
}

//register callbacks with library
void CRYPTO_set_dynlock_create_callback(dyn_create_func);
void CRYPTO_set_dynlock_lock_callback(dyn_lock_func);
void CRYPTO_set_dynlock_destroy_callback(dyn_destroy_func);


static void show_help(int argc, char *argv[]){
	printf("Usage:\n");
	printf("  %s <port to listen on> [-h] [-u] [-6] [-f]\n", argv[0]);
	printf("Options:\n");
    printf("  -h              show help\n");
    printf("  -u              create a UDP listener\n");
	printf("  -6              accept IPv6 connections only for IPv6 listener\n");
	printf("  -f <file_path>  queue file to send when connection is made\n");
}

int main(int argc, char *argv[]){
    SSL_CTX *ctx;
    int server;
    int port;
    int opt;

    if(!isRoot()){
        printf("This program must be run as root/sudo user!!");
        exit(0);
    }

    if ( argc < 2 ){
        show_help(argc, argv);
        exit(0);
    }
    port = atoi(argv[1]);

    while ((opt = getopt(argc, argv, "uh6f:")) != -1) {
        switch (opt) {
        case 'u':
            udp = true;
            break;
        case 'h':
            show_help(argc, argv);
            exit(0);
            break;
        case '6':
            is_v6 = true;
            break;
        case 'f':
            file = optarg;
        case '?':
            exit(1);
        }
    }

    SSL_library_init();
    
    if (udp == true){
        DTLSServer(port);
    }
    
    ctx = InitServerCTX();        /* initialize SSL */
    LoadCertificates(ctx, "mycert.pem", "mycert.pem"); /* load certs */
    server = OpenListener(port);    /* create server socket */
    for( ;; ){
        struct sockaddr_in addr;
        socklen_t len = sizeof(addr);
        SSL *ssl;
 
        int client = accept(server, (struct sockaddr*)&addr, &len);  /* accept connection as usual */
        printf("Connection: %s:%d\n",inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));
        ssl = SSL_new(ctx);              /* get new SSL state with context */
        SSL_set_fd(ssl, client);      /* set connection socket to SSL state */
        Servlet(ssl);         /* service connection */
    }
    close(server);          /* close server socket */
    SSL_CTX_free(ctx);         /* release context */
}