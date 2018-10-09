# Encrypted-Chat-Server-Using-C-Programming-and-OpenSSL-AES-DES

This is a client - server user-level application using sockets Programming in C. Server accepts strings from client and can reply to client. Both server and client(s) output's of chat shows on terminal.The server and client processes can run on same or different machines. Server and client connection is encrypted, send and receive messages can't be traced by any intruder as we are using OpenSSL certificates for encryption. In this post only we will have a brief overview of creating Openssl certificates using OpenSSL tool.

 > Various Features Included  :

    * Usage of Socket Programming for creating Client & Server program
    * Multi-threading for Full Duplex Communication between Client and Server
    * Encrypted Communication between Client and Server 
    * Usage of Basic Networking Concepts & Linux Os for executing client and server programs


> Future Improvements :

    - Accept multiple Clients 
    - Create Chat Logs between client and server
    - Add file transfer + Video conferencing (need to use Java | Python programming)
    - Using C graphics library add GUI (graphics user interface)
    - Name and rename users | Block clients
    
### Server.c
    
```C++
#include <unistd.h> /*FOR USING FORK for at a time send and receive messages*/ 

	#include <errno.h>   /*USING THE ERROR LIBRARY FOR FINDING ERRORS*/
#include <malloc.h>  /*FOR MEMORY ALLOCATION */

	#include <string.h>  /*using fgets funtions for geting input from user*/

	#include <arpa/inet.h>  /*for using ascii to network bit*/ 

	#include <sys/socket.h>  /*for creating sockets*/

	#include <sys/types.h>  /*for using sockets*/

	#include <netinet/in.h>        /* network to asii bit */

	#include <resolv.h>  /*server to find out the runner's IP address*/ 

	#include "openssl/ssl.h" /*using openssl function's and certificates and configuring them*/

	#include "openssl/err.h" /* helps in finding out openssl errors*/

	#include <stdio.h>   /*standard i/o*/

	#define FAIL    -1  /*for error output == -1 */

	#define BUFFER 1024  /*buffer for reading messages*/

	

	int OpenListener(int port)   

	{   int sd;

	struct sockaddr_in addr;   /*creating the sockets*/

	

	sd = socket(PF_INET, SOCK_STREAM, 0);

	bzero(&addr, sizeof(addr));    /*free output the garbage space in memory*/

	addr.sin_family = AF_INET;    /*getting ip address form machine */

	addr.sin_port = htons(port);   /* converting host bit to n/w bit */

	addr.sin_addr.s_addr = INADDR_ANY;

	if ( bind(sd, (struct sockaddr*)&addr, sizeof(addr)) != 0 ) /* assiging the ip address and port*/

	{

	perror("can't bind port");    /* reporting error using errno.h library */

	abort();      /*if error will be there then abort the process */

	}

	if ( listen(sd, 10) != 0 )     /*for listening to max of 10 clients in the queue*/

	{

	perror("Can't configure listening port");  /* reporting error using errno.h library */

	abort();      /*if erroor will be there then abort the process */

	}

	return sd;

	}

	

	int isRoot()        /*for checking if the root user is executing the server*/

	{

	if (getuid() != 0)    

	{

	return 0;

	}

	else

	{

	return 1;       /* if root user is not executing report must be user */  

	}

	

	}

	SSL_CTX* InitServerCTX(void)      /*creating and setting up ssl context structure*/

	{   SSL_METHOD *method;

	SSL_CTX *ctx;       

	

	OpenSSL_add_all_algorithms();       /* load & register all cryptos, etc. */

	SSL_load_error_strings();        /* load all error messages */

	method = TLSv1_2_server_method();       /* create new server-method instance */

	ctx = SSL_CTX_new(method);        /* create new context from method */

	if ( ctx == NULL )

	{

	ERR_print_errors_fp(stderr);

	abort();

	}

	return ctx;

	}

	

	void LoadCertificates(SSL_CTX* ctx, char* CertFile, char* KeyFile)   /* to load a certificate into an SSL_CTX structure*/

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

	

	void ShowCerts(SSL* ssl)     /*show the ceritficates to client and match them*/

	{   X509 *cert;

	char *line;

	

	cert = SSL_get_peer_certificate(ssl); /* Get certificates (if available) */

	if ( cert != NULL )

	{

	printf("Server certificates:\n");

	line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);  

	printf("Server: %s\n", line);     /*server certifcates*/

	free(line);

	line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);

	printf("client: %s\n", line);     /*client certificates*/

	free(line);

	X509_free(cert);

	}

	else

	printf("No certificates.\n");

	}

	

	void Servlet(SSL* ssl) /* Serve the connection -- threadable */

	{   char buf[1024];

	int sd, bytes;

	char input[BUFFER];  

	pid_t cpid; 

	if ( SSL_accept(ssl) == FAIL )     /* do SSL-protocol accept */

	ERR_print_errors_fp(stderr);

	else

	{ 

	ShowCerts(ssl);        /* get any certificates */

	/*Fork system call is used to create a new process*/

	cpid=fork();

	if(cpid==0)

	{ 

	while(1){

	bytes = SSL_read(ssl, buf, sizeof(buf)); /* get request and read message from server*/

	

	if ( bytes > 0 )

	{ 

	buf[bytes] = 0;

	printf("\nMESSAGE FROM SERVER:%s\n", buf);

	

	}  

	else

	ERR_print_errors_fp(stderr);

	} }

	else {

	

	while(1){

	

	printf("\nMESSAGE TO CLIENT:");

	fgets(input, BUFFER, stdin);  /* get request and reply to client*/

	

	SSL_write(ssl, input, strlen(input)); 

	}

	

	}  

	}

	sd = SSL_get_fd(ssl);       /* get socket connection */

	SSL_free(ssl);         /* release SSL state */

	close(sd);          /* close connection */

	}

	

	int main(int count, char *strings[])   /* getting port as a argument*/

	{   SSL_CTX *ctx;

	int server;

	char *portnum;

	

	

	if(!isRoot())        /* if root user is not executing server report must be root user */

	{

	printf("This program must be run as root/sudo user!!");

	exit(0);

	}

	if ( count != 2 )

	{

	printf("Usage: %s \n", strings[0]);   /*send the usage guide if syntax of setting port is different*/

	exit(0);

	}

	SSL_library_init();                                                 /*load encryption and hash algo's in ssl*/

	

	portnum = strings[1];

	ctx = InitServerCTX();        /* initialize SSL */

	LoadCertificates(ctx, "certi.pem", "certi.pem"); /* load certs */

	server = OpenListener(atoi(portnum));    /* create server socket */

	

	struct sockaddr_in addr;      /*socket for server*/

	socklen_t len = sizeof(addr);

	SSL *ssl;

	listen(server,5);      /*setting 5 clients at a time to queue*/

	int client = accept(server, (struct sockaddr*)&addr, &len);  /* accept connection as usual */

	printf("Connection: %s:%d\n",inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));  /*printing connected client information*/

	ssl = SSL_new(ctx);              /* get new SSL state with context */

	SSL_set_fd(ssl, client);      /* set connection socket to SSL state */

	

	Servlet(ssl);         /* service connection */

	

	close(server);          /* close server socket */

	SSL_CTX_free(ctx);         /* release context */

	}


```

### Client.c

```C++
#include <errno.h> /*USING THE ERROR LIBRARY FOR FINDING ERRORS*/

	

#include <stdio.h> /*standard i/o*/


#include <unistd.h> /*FOR USING FORK for at a time send and receive messages*/ 

	#include <malloc.h> /*FOR MEMORY ALLOCATION */

	#include <string.h> /*using fgets funtions for geting input from user*/

	#include <sys/socket.h> /*for creating sockets*/

	#include <resolv.h> /*server to find out the runner's IP address*/ 

	#include <netdb.h> /*definitions for network database operations */

	#include <openssl/ssl.h> /*using openssl function's and certificates and configuring them*/

	#include <openssl/err.h> /* helps in finding out openssl errors*/

	#include <unistd.h>  /*FOR USING FORK for at a time send and receive messages*/ 

	

	#define FAIL    -1 /*for error output == -1 */

	#define BUFFER  1024  /*buffer for reading messages*/

	int OpenConnection(const char *hostname, int port)

	{   int sd;

	struct hostent *host;

	struct sockaddr_in addr;   /*creating the sockets*/

	

	if ( (host = gethostbyname(hostname)) == NULL )

	{

	perror(hostname);

	abort();

	}

	sd = socket(PF_INET, SOCK_STREAM, 0);   /* setting the connection as tcp it creates endpoint for connection */

	bzero(&addr, sizeof(addr));

	addr.sin_family = AF_INET;

	addr.sin_port = htons(port);

	addr.sin_addr.s_addr = *(long*)(host->h_addr);

	if ( connect(sd, (struct sockaddr*)&addr, sizeof(addr)) != 0 )  /*initiate a connection on a socket*/

	{

	close(sd);

	perror(hostname);

	abort();

	}

	return sd;

	}

	

	SSL_CTX* InitCTX(void)     /*creating and setting up ssl context structure*/

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

	

	void ShowCerts(SSL* ssl)  /*show the ceritficates to server and match them but here we are not using any client certificate*/

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

	

	int main(int count, char *strings[])   /* getting port and ip as an argument*/

	{   SSL_CTX *ctx;

	int server;

	SSL *ssl;

	char buf[1024];

	char input[BUFFER];

	int bytes;

	char *hostname, *portnum;

	pid_t cpid;     /* fork variable*/

	

	if ( count != 3 )

	{

	printf("usage: %s  \n", strings[0]);

	exit(0);

	}

	SSL_library_init();   /*load encryption and hash algo's in ssl*/

	hostname=strings[1];

	portnum=strings[2];

	

	ctx = InitCTX();

	server = OpenConnection(hostname, atoi(portnum));   /*converting ascii port to interger */

	ssl = SSL_new(ctx);      /* create new SSL connection state */

	SSL_set_fd(ssl, server);    /* attach the socket descriptor */

	if ( SSL_connect(ssl) == FAIL )   /* perform the connection */

	ERR_print_errors_fp(stderr);

	else

	

	{    

	

	

	printf("Connected with %s encryption\n", SSL_get_cipher(ssl));

	ShowCerts(ssl);

	/* get any certs */

	cpid=fork();

	/*Fork system call is used to create a new process*/

	if(cpid==0)

	{

	while(1){

	printf("\nMESSAGE TO SERVER:");

	fgets(input, BUFFER, stdin);

	

	SSL_write(ssl, input, strlen(input));   /* encrypt & send message */}}

	else {

	while(1)

	{

	

	bytes = SSL_read(ssl, buf, sizeof(buf)); /* get request */

	

	if ( bytes > 0 )

	{ 

	buf[bytes] = 0;

	printf("\nMESSAGE FROM CLIENT: %s\n", buf);

	}

	

	} }

	SSL_free(ssl);        /* release connection state */

	

	

	}   close(server);         /* close socket */

	SSL_CTX_free(ctx);        /* release context */

	

	return 0;

	}
	
```


> Executing Commands :

>> Creating OpenSSL certificates :

openssl req -x509 -nodes -days 365 -newkey rsa:1024 -keyout mycert.pem -out mycert.pem

Creating certificate with Authentication:

OpenSSL Guide: https://help.ubuntu.com/community/OpenSS


Compiling Server.c :

Command Line : gcc -Wall -o ssl-server ssl-server.c -L/usr/lib -lssl -lcrypto


Executing Server :

Command Line : sudo ./ssl-server || Ex: sudo ./ssl-server 6000


Compiling Client.c :

  Command Line : gcc -Wall -o ssl-client ssl-client.c -L/usr/lib -lssl -lcrypto


Executing Client :

Command Line : ./ssl-client   || ./ssl-client 192.168.43.54 6000


Monitoring Traffic using ssldump :

ssldump -i wlan0 port 6000


