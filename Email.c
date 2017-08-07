#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <malloc.h>
#include <string.h>
#include <sys/socket.h>
#include <resolv.h>
#include <netdb.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <unistd.h>

#define FAIL    -1

int OpenConnection(const char *hostname, int port)
{   int sd;
    struct hostent *host;
    struct sockaddr_in addr;

    if ( (host = gethostbyname(hostname)) == NULL )
    {
        perror(hostname);
        abort();
    }
    sd = socket(PF_INET, SOCK_STREAM, 0);
    bzero(&addr, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = *(long*)(host->h_addr);
    if ( connect(sd, (struct sockaddr*)&addr, sizeof(addr)) != 0 )
    {
        close(sd);
        perror(hostname);
        abort();
    }
    return sd;
}

SSL_CTX* InitCTX(void)
{   SSL_METHOD *method;
    SSL_CTX *ctx;

    OpenSSL_add_all_algorithms();  /* Load cryptos, et.al. */
    SSL_load_error_strings();   /* Bring in and register error messages */
    method = TLSv1_2_client_method();  /* Create new client-method instance */
    ctx = SSL_CTX_new(method);   /* Create new context */
    if ( ctx == NULL )
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
    return ctx;
}

void ShowCerts(SSL* ssl)
{   X509 *cert;
    char *line;

    cert = SSL_get_peer_certificate(ssl); /* get the server's certificate */
    if ( cert != NULL )
    {
        printf("Server certificates:\n");
        line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
        printf("Subject: %s\n", line);
        free(line);       /* free the malloc'ed string */
        line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
        printf("Issuer: %s\n", line);
        free(line);       /* free the malloc'ed string */
        X509_free(cert);     /* free the malloc'ed certificate copy */
    }
    else
        printf("Info: No client certificates configured.\n");
}

int main(int count, char *strings[])
{   SSL_CTX *ctx;
    int server;
    SSL *ssl;
    char buf[1024];
    int bytes;
    char *hostname, *portnum;

    if ( count != 3 )
    {
        printf("usage: %s <hostname> <portnum>\n", strings[0]);
        exit(0);
    }
    SSL_library_init();
    hostname=strings[1];
    portnum=strings[2];

    ctx = InitCTX();
    server = OpenConnection(hostname, atoi(portnum));
    ssl = SSL_new(ctx);      /* create new SSL connection state */
    SSL_set_fd(ssl, server);    /* attach the socket descriptor */
    if ( SSL_connect(ssl) == FAIL )   /* perform the connection */
        ERR_print_errors_fp(stderr);
    else
    {   
	printf("Connected with %s encryption\n", SSL_get_cipher(ssl));
        ShowCerts(ssl);        /* get any certs */

	char* VE_HELO = (unsigned char*) malloc(strlen("EHLO ") + strlen("vitz.com.mx") + strlen("\r\n") + 1);
	int offset = 0;
	strncpy(VE_HELO+offset,"EHLO ",strlen("EHLO "));
	offset += strlen("EHLO ");

	strncpy(VE_HELO+offset,"vitz.com.mx",strlen("vitz.com.mx"));
	offset += strlen("vitz.com.mx");

	strncpy(VE_HELO+offset,"\r\n",strlen("\r\n"));
	offset += strlen("\r\n");

	memset(VE_HELO+offset,0,1);

	char* VE_USER = (unsigned char*) malloc(strlen("==") + strlen("\r\n") + 1);
	offset = 0;
	strncpy(VE_USER+offset,"==",strlen("=="));
	offset += strlen("==");

	strncpy(VE_USER+offset,"\r\n",strlen("\r\n"));
	offset += strlen("\r\n");

	memset(VE_USER+offset,0,1);

	char* VE_PASSWORD = (unsigned char*) malloc(strlen("=") + strlen("\r\n") + 1);
	offset = 0;
	strncpy(VE_PASSWORD+offset,"=",strlen("="));
	offset += strlen("=");

	strncpy(VE_PASSWORD+offset,"\r\n",strlen("\r\n"));
	offset += strlen("\r\n");

	memset(VE_PASSWORD+offset,0,1);

	char* VE_FROM = (unsigned char*) malloc(strlen("MAIL FROM:<") + strlen("carlos.pineda@vitz.com.mx") + strlen(">\r\n") + 1);
	offset = 0;
	strncpy(VE_FROM+offset,"MAIL FROM:<",strlen("MAIL FROM:<"));
	offset += strlen("MAIL FROM:<");

	strncpy(VE_FROM+offset,"carlos.pineda@vitz.com.mx",strlen("carlos.pineda@vitz.com.mx"));
	offset += strlen("carlos.pineda@vitz.com.mx");

	strncpy(VE_FROM+offset,">\r\n",strlen(">\r\n"));
	offset += strlen(">\r\n");

	memset(VE_FROM+offset,0,1);

	char* VE_TO = (unsigned char*) malloc(strlen("RCPT TO:<") + strlen("car_1253@hotmail.com") + strlen(">\r\n") + 1);
	offset = 0;
	strncpy(VE_TO+offset,"RCPT TO:<",strlen("RCPT TO:<"));
	offset += strlen("RCPT TO:<");

	strncpy(VE_TO+offset,"car_1253@hotmail.com",strlen("car_1253@hotmail.com"));
	offset += strlen("car_1253@hotmail.com");

	strncpy(VE_TO+offset,">\r\n",strlen(">\r\n"));
	offset += strlen(">\r\n");

	memset(VE_TO+offset,0,1);

	char* headers = (unsigned char*) malloc(strlen("From: Sistema Vitz <") + strlen("carlos.pineda@vitz.com.mx") + strlen(">\r\nTo: <") +
	strlen("car_1253@hotmail.com") + strlen(">\r\nSubject: Alarma de fuga\r\n") + 1);

	offset = 0;
	strncpy(headers+offset,"From: Sistema Vitz <",strlen("From: Sistema Vitz <"));
	offset += strlen("From: Sistema Vitz <");

	strncpy(headers+offset,"carlos.pineda@vitz.com.mx",strlen("carlos.pineda@vitz.com.mx"));
	offset += strlen("carlos.pineda@vitz.com.mx");

	strncpy(headers+offset,">\r\nTo: <",strlen(">\r\nTo: <"));
	offset += strlen(">\r\nTo: <");

	strncpy(headers+offset,"car_1253@hotmail.com",strlen("car_1253@hotmail.com"));
	offset += strlen("car_1253@hotmail.com");

	strncpy(headers+offset,">\r\nSubject: Alarma de fuga\r\n",strlen(">\r\nSubject: Alarma de fuga\r\n"));
	offset += strlen(">\r\nSubject: Alarma de fuga\r\n");

	memset(headers+offset,0,1);
    
	char* DataEmail = (unsigned char*) malloc(strlen("Se detecto una fuga.\r\n \r\nIndustrias Vitz S.A. de C.V.\r\nTel. 2226 72 98 58\r\nsoporte@vitz.com.mx\r\nwww.vitz.com.mx\r\n")+1);
	offset = 0;
	strncpy(DataEmail+offset,"Se detecto una fuga.\r\n \r\nIndustrias Vitz S.A. de C.V.\r\nTel. 2226 72 98 58\r\nsoporte@vitz.com.mx\r\nwww.vitz.com.mx\r\n",strlen("Se detecto una fuga.\r\n \r\nIndustrias Vitz S.A. de C.V.\r\nTel. 2226 72 98 58\r\nsoporte@vitz.com.mx\r\nwww.vitz.com.mx\r\n"));
	offset += strlen("Se detecto una fuga.\r\n \r\nIndustrias Vitz S.A. de C.V.\r\nTel. 2226 72 98 58\r\nsoporte@vitz.com.mx\r\nwww.vitz.com.mx\r\n");
    
	memset(DataEmail+offset,0,1);

	char *msg = "Hello???";

	SSL_write(ssl, VE_HELO, strlen(VE_HELO));
	bytes = SSL_read(ssl, buf, sizeof(buf));
	buf[bytes] = 0;
        printf("Received: \"%s\"\n", buf);

	SSL_write(ssl, "AUTH LOGIN\r\n", strlen("AUTH LOGIN\r\n"));
	bytes = SSL_read(ssl, buf, sizeof(buf));
	buf[bytes] = 0;
        printf("Received: \"%s\"\n", buf);

	SSL_write(ssl, VE_USER, strlen(VE_USER));
	bytes = SSL_read(ssl, buf, sizeof(buf));
	buf[bytes] = 0;
        printf("Received: \"%s\"\n", buf);

	SSL_write(ssl, VE_PASSWORD, strlen(VE_PASSWORD));
	bytes = SSL_read(ssl, buf, sizeof(buf));
	buf[bytes] = 0;
        printf("Received: \"%s\"\n", buf);

	SSL_write(ssl, VE_FROM, strlen(VE_FROM));
	bytes = SSL_read(ssl, buf, sizeof(buf));
	buf[bytes] = 0;
        printf("Received: \"%s\"\n", buf);

	SSL_write(ssl, VE_TO, strlen(VE_TO));
	bytes = SSL_read(ssl, buf, sizeof(buf));
	buf[bytes] = 0;
        printf("Received: \"%s\"\n", buf);

	SSL_write(ssl, "DATA\r\n", strlen("DATA\r\n"));
	bytes = SSL_read(ssl, buf, sizeof(buf));
	buf[bytes] = 0;
        printf("Received: \"%s\"\n", buf);

	SSL_write(ssl, headers, strlen(headers));
	SSL_write(ssl, DataEmail, strlen(DataEmail));
	SSL_write(ssl, "\r\n.\r\n", strlen("\r\n.\r\n"));
	bytes = SSL_read(ssl, buf, sizeof(buf));
	buf[bytes] = 0;
        printf("Received: \"%s\"\n", buf);

	SSL_write(ssl, "QUIT\r\n", strlen("QUIT\r\n"));
	bytes = SSL_read(ssl, buf, sizeof(buf));
	buf[bytes] = 0;
        printf("Received: \"%s\"\n", buf);

        SSL_free(ssl);        /* release connection state */
    }
    close(server);         /* close socket */
    SSL_CTX_free(ctx);        /* release context */
    return 0;
}
