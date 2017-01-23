// Name: server.c
// Purpose: Secure cloud storage server using TLS 1.2
// Author: Edward Lee (el1926), Shikang Zheng (sz1389)

#include <unistd.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <dirent.h>

//certificate, key, and storage locations
#define S_CERT	"server/server.crt"	
#define	S_KEY	"server/server.key"
#define C_CA	"server/client.crt"
#define S_DIR	"storage/"    

void initCTX(SSL_CTX *context)
{
    //load server certificate and private key
    if (!SSL_CTX_use_certificate_file(context, S_CERT, SSL_FILETYPE_PEM) ||
	!SSL_CTX_use_PrivateKey_file(context, S_KEY, SSL_FILETYPE_PEM) ||
	!SSL_CTX_check_private_key(context))
    {
	fprintf(stderr, "error: certificates\n");
	ERR_print_errors_fp(stderr);
	abort();
    }
    
    //load client CA certificate for verification
    if (SSL_CTX_load_verify_locations(context, C_CA, NULL) != 1)
    {
	fprintf(stderr, "error: loading verify CA\n");
	ERR_print_errors_fp(stderr);
	abort();
    }
    
    //load list of acceptable certificate names to be sent to client
    STACK_OF(X509_NAME) *list;
    list = SSL_load_client_CA_file(C_CA);
    if (list == NULL)
    {
	fprintf(stderr, "error: loading client CA\n");
	ERR_print_errors_fp(stderr);
	abort();
    }
    SSL_CTX_set_client_CA_list(context, list);

    //force client to send certificate
    SSL_CTX_set_verify(context, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);

    //automatic curve selection for ECDHE
    SSL_CTX_set_ecdh_auto(context, 1);

    //set cipher
    SSL_CTX_set_cipher_list(context, "ECDHE_ECDSA_AES_128_GCM_SHA256");
}

int service(BIO *bio, char c);

int listDir(BIO *bio)
{
    char filename[128] = "l";
    char *done = "b\n";
    DIR *dir;
    struct dirent *ent;
    if ((dir = opendir(S_DIR)) != NULL) 
    {
	while ((ent = readdir(dir)) != NULL) 
	{   
	    //keep files hidden
	    if (strncmp(ent->d_name, ".", 1) == 0 || strncmp(ent->d_name, "..", 2) == 0)
	    {
		continue;
	    }
	    filename[1] = 0;
	    strcat(filename, ent->d_name);
	    strcat(filename, "\n");
	    if (!BIO_write(bio, filename, strlen(filename)))
	    {
		return -1;
	    }
	}
	closedir(dir);

    } else 
    {
	perror("Could not open directory\n");
	return -1;
    }
    
    if (!BIO_write(bio, done, strlen(done)))
    {
	return -1;
    }
    return 1;
}

int removeFile(BIO *bio, char *filename)
{
    char path[128] = S_DIR;
    strcat(path, filename);

    remove(path);
    return 1;
}

int fileDownload(BIO *bio, char *fn)
{
    char rbuf[1024], sfn[128] = S_DIR;
    FILE *fp;
    int len;
    
    printf("%s ~> server.. ", fn);
    fflush(stdout);
    
    //save location
    strcat(sfn, fn);
    
    fp = fopen(sfn, "wb");
    if (!fp)
    {
	printf("%s ", strerror(errno));
	return -1;
    }
    
    //downloading file
    do 
    {
	if ((len = BIO_read(bio, rbuf, sizeof(rbuf))) <= 0)
	    return -1;
	fwrite(rbuf + 1, 1, len - 2, fp);
    } while (rbuf[0] == 'u');
    
    printf("done\n");

    //cleanup
    fclose(fp);

    return 1;
}

int fileUpload(BIO *bio, char *filename)
{
    char buf[1024] = "u", sfn[128] = S_DIR, wbuf[4] = "b\n";
    FILE *fp;
    int len;

    printf("%s ~> client.. ", filename);
    fflush(stdout);
    
    //filename
    strcat(sfn, filename);

    fp = fopen(sfn, "rb");
    if (!fp)
    {
        printf("%s\n", strerror(errno));
	return 0;
    }

    //uploading
    while ((len = fread(buf + 1, sizeof(char), 1020, fp)) == 1020) 
    {
	if (BIO_write(bio, buf, len + 2) <= 0)
	{
	    fclose(fp);
	    return -1;
	}
    }

    if (len > 0 && len != 1020)
    {
	buf[len + 1] = '\n';
	if (BIO_write(bio, buf, len + 2) <= 0)
	{
	    fclose(fp);
	    return -1;
	}
    }

    BIO_write(bio, wbuf, strlen(wbuf));
    
    printf("done\n");

    //cleanup
    fclose(fp);
    return 1;
}

//check if file exists
int checkFile(char *filename)
{
    char sfn[128] = S_DIR;
    FILE *fp;
    
    if (strlen(filename) == 0)
	return 0;
    
    strcat(sfn, filename);
    
    fp = fopen(sfn, "rb");
    if (!fp)
	return 0;
    
    fclose(fp);
    return 1;
	
}

int handleU(BIO *bio)
{
    char fn[128];
    int len;

    if ((len = BIO_read(bio, fn, sizeof(fn))) <= 0)
	return -1;
    if (fn[0] == 'b')
	return 1;

    fn[len] = 0;

    return fileDownload(bio, fn + 1);
}

int handleD(BIO *bio)
{
    int len, ret = 0;
    char rbuf[128], buf[128];
    char *fn, *filename, *dl = "d\n", *back = "b - back\n", *err = "error: file not found\n";
    while (1)
    {
	if (!listDir(bio))
	    return -1;
	if (BIO_write(bio, back, strlen(back)) <= 0)
	    return -1;
	if ((len = BIO_read(bio, rbuf, sizeof(rbuf))) <= 0)
	    return -1;
	rbuf[len] = 0;

	if (strcmp(rbuf, "b\n") == 0)
	{
	    service(bio, 'o');
	    return 1;
	}
	rbuf[strlen(rbuf) - 1] = 0;

	//remove any '/'
	fn = strrchr(rbuf, '/');
	if (fn == NULL)
	    filename = rbuf;
	else
	    filename = fn + 1;
	
	//check if file exists
	if (!checkFile(filename))
	{
	    if (BIO_write(bio, err, strlen(err)) <= 0)
		return -1;
	    continue;
	}
	
	//ask client to continue
	if (BIO_write(bio, dl, strlen(dl)) <= 0)
	    return -1;
	
	//client cancels
	if (BIO_read(bio, buf, sizeof(buf)) <= 0)
	    return -1;

	if (buf[0] == 'b')
	{
	    continue;
    	}

	break;
    }
    
    //upload file
    ret = fileUpload(bio, filename);
    if (ret < 0)
	return ret;
    return service(bio, 'o');
}

int handleR(BIO *bio)
{
    char *fn, *filename;
    char rbuf[128];
    char cnt[4] = "c\n";
    char back[12] = "b - back\n";
    char err[24] = "error: file not found\n";
    char rop[28] = "r: select file to remove\n";
    int len;

    while (1)
    {
	if (!listDir(bio))
	    return -1;
	if (BIO_write(bio, back, strlen(back)) <= 0)
	    return -1;
	if ((len = BIO_read(bio, rbuf, sizeof(rbuf))) <= 0)
	    return -1;
	rbuf[len] = 0;
	
	//if client wants to go back
	if (strcmp(rbuf, "b\n") == 0)
	{
	    service(bio, 'o');
	    return 1;
	}

	rbuf[strlen(rbuf) - 1] = 0; 

	//remove and '/'
	fn = strrchr(rbuf, '/');
	if (fn == NULL)
	    filename = rbuf;
	else
	    filename = fn + 1;

	//check if file exists
	if (!checkFile(filename))
	{
	    if (BIO_write(bio, err, strlen(err)) <= 0)
		return -1;
	    continue;
	}
	
	//tell client which file is being removed
	if (BIO_write(bio, cnt, strlen(cnt)) <= 0)
	    return -1;
	
	//remove file
	printf("removing %s.. ", filename);
	fflush(stdin);
	removeFile(bio, filename);
	printf("done\n");
	
	//tell client done
	if (BIO_write(bio, rop, strlen(rop)) <= 0)
	    return -1;    
    }
        
}

//first letter tells client what operation it is
int service(BIO *bio, char c)
{
    const char *invld = "invalid input, try again. o for options\n";
    const char *dl = "d: select file to download\n";
    const char *ul = "u: select file to upload\n";
    const char *rm = "r: select file to remove\n";
    const char *ls = "l: list files\n";
    const char *quit = "q: exiting.\n";
    const char *ops =	"o - options\n"
			"u - upload\n"
			"d - download\n"
			"l - list\n"
			"r - remove\n"
			"q - quit\n";

    switch(c) 
    {	
	case 'd':
	    if(!BIO_write(bio, dl, strlen(dl)))
		return -1;
	    return handleD(bio);
	case 'u':
	    if (!BIO_write(bio, ul, strlen(ul)))
		return -1;
	    return handleU(bio);
	case 'r':
	    if (!BIO_write(bio, rm, strlen(rm)))
		return 1;
	    return handleR(bio);
	case 'l':
	    if (!BIO_write(bio, ls, strlen(ls)))
		return -1;
	    return listDir(bio);
	case 'o':
	    if (!BIO_write(bio, ops, strlen(ops)))
		return -1;
	    return 1;
	case 'q':
	    if (!BIO_write(bio, quit, strlen(quit)))
		return -1;
	    return -1;
	default: 
	    if (!BIO_write(bio, invld, strlen(invld)))
		return -1;
	    return 1;
    }
}

void closeConn(BIO *bio)
{	
    BIO_free(bio);
    printf("connection closed.\n");
}

void getClientInfo(BIO *bio, struct sockaddr_in *addr)
{	
    socklen_t addrlen;
    int sock_fd;
    addrlen = sizeof(*addr);
    BIO_get_fd(bio, &sock_fd);
    getpeername(sock_fd, (struct sockaddr *)addr, &addrlen);
}

int main(int argc, char *argv[])
{
    struct sockaddr_in addr;
    BIO *sslbio, *acpt;
    SSL_CTX *context;
    SSL *ssl;
    
    if (argc != 2)
    {
	printf("usage: %s <port>\n", argv[0]);
	exit(0);
    }

    //initialize ssl library
    SSL_library_init();

    //crypto algorithms and error messages
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();

    //create server context
    context = SSL_CTX_new(TLSv1_2_server_method()); /* TLS v1.2 */
    if (context == NULL)
    {	
	fprintf(stderr, "error: setting up context");
	ERR_print_errors_fp(stderr);
	abort();
    }
    initCTX(context);
    
    //initialize BIO listener
    sslbio = BIO_new_ssl(context, 0);
    acpt = BIO_new_accept(argv[1]);
    BIO_set_accept_bios(acpt, sslbio);
    
    //get back ssl state
    BIO_get_ssl(sslbio, &ssl);

    if(BIO_do_accept(acpt) <= 0) 
    {
	fprintf(stderr, "error: setting up accept BIO\n");
        ERR_print_errors_fp(stderr);
	abort();
    }

    //loop forever accepting connection
    while (1)
    {
	int len;
	char rbuf[1024], 
	wbuf[128] = 
	"Secure cloud storage service v1.0\n"
	"Select action:\n"
	"o - options\n"
	"u - upload\n"
	"d - download\n"
	"l - list\n"
	"r - remove\n"
	"q - quit\n";

	//accept connection
	printf("waiting for connection..\n");
	if(BIO_do_accept(acpt) <= 0)
	{
	    fprintf(stderr, "error: connection\n");
	    ERR_print_errors_fp(stderr);
	    abort();
        }
	
	//get connection
	sslbio = BIO_pop(acpt);

	//tls handshake
	if(BIO_do_handshake(sslbio) <= 0) 
	{
	    fprintf(stderr, "error: TLS handshake\n");
	    ERR_print_errors_fp(stderr);
	    return(0);
	}
	
	getClientInfo(sslbio, &addr);

	//TLS connection
	printf("Connection: %s:%d\n", inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));
	if (!BIO_write(sslbio, wbuf, strlen(wbuf)))
	{
	    closeConn(sslbio);
	    continue;
	}

	do 
	{   
	    if ((len = BIO_read(sslbio, rbuf, sizeof(rbuf))) <= 0)
	    {
		break;
	    }
	    rbuf[len] = 0;

	} while (service(sslbio, rbuf[0]) > 0);
	
	//close connection
	closeConn(sslbio);
    }
    
    //clean up
    SSL_free(ssl);
    SSL_CTX_free(context);
    EVP_cleanup();
}
