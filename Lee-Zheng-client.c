// Name: client.c
// Purpose: Client for secure cloud storage using TLS 1.2
// Author: Edward Lee (el1926), Shikang Zheng (sz1389)

#include <unistd.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netdb.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/bio.h>
#include <openssl/aes.h>
#include "tinyfiledialogs.h"

//certificate and key locations
#define cert	"client/client.crt"
#define key	"client/client.key"
#define server	"server/server.crt"
#define AES_KEY	"4A6*9FD29$F5860"
#define AES_IV	"FB#0AD052!9C519"

void initCTX(SSL_CTX* context)
{
    //load client certificate and private key
    if (!SSL_CTX_use_certificate_file(context, cert, SSL_FILETYPE_PEM) ||
	!SSL_CTX_use_PrivateKey_file(context, key, SSL_FILETYPE_PEM) ||
	!SSL_CTX_check_private_key(context))
    {
	fprintf(stderr, "error: certificates");
	ERR_print_errors_fp(stderr);
	abort();
    }

    //load client CA certificate for verification
    if (SSL_CTX_load_verify_locations(context, server, NULL) != 1)
    {
	fprintf(stderr, "error: loading verify CA");
	ERR_print_errors_fp(stderr);
	abort();
    }

    SSL_CTX_set_verify(context, SSL_VERIFY_PEER, NULL);

    //set cipher
    SSL_CTX_set_cipher_list(context, "ECDHE-ECDSA-AES128-GCM-SHA256");
}


void encrypt(FILE *ifp, FILE *ofp)
{   
    //aes key and iv
    unsigned char ckey[] = AES_KEY;
    unsigned char ivec[] = AES_IV;

    //get file size
    fseek(ifp, 0L, SEEK_END);
    int fsize = ftell(ifp);
    
    //set back to normal
    fseek(ifp, 0L, SEEK_SET);
    
    int outLen1 = 0; int outLen2 = 0;
    
    //memory to store file
    unsigned char *indata = malloc(fsize);
    unsigned char *outdata = malloc(fsize * 2);

    //read file
    fread(indata,sizeof(char), fsize, ifp);

    //set up encryption
    EVP_CIPHER_CTX ctx;
    EVP_EncryptInit(&ctx, EVP_aes_128_gcm(), ckey, ivec);

    //encrypt
    EVP_EncryptUpdate(&ctx, outdata, &outLen1, indata, fsize);
    EVP_EncryptFinal(&ctx, outdata + outLen1, &outLen2);
    
    //write to file
    fwrite(outdata, sizeof(char), outLen1 + outLen2, ofp);

    //cleanup
    free(indata);
    free(outdata);
}

void decrypt(FILE *ifp, FILE *ofp)
{
    //aes key and iv
    unsigned char ckey[] = AES_KEY;
    unsigned char ivec[] = AES_IV;

    //get file size
    fseek(ifp, 0L, SEEK_END);
    int fsize = ftell(ifp);
    
    //set back to normal
    fseek(ifp, 0L, SEEK_SET);

    int outLen1 = 0; int outLen2 = 0;
    
    //memory to store file
    unsigned char *indata = malloc(fsize);
    unsigned char *outdata = malloc(fsize);
    
    //read File
    fread(indata, sizeof(char), fsize, ifp);

    //setup decryption
    EVP_CIPHER_CTX ctx;
    EVP_DecryptInit(&ctx, EVP_aes_128_gcm(), ckey, ivec);

    //decrypt
    EVP_DecryptUpdate(&ctx, outdata, &outLen1, indata, fsize);
    EVP_DecryptFinal(&ctx, outdata + outLen1, &outLen2);
    
    //write to file
    fwrite(outdata, sizeof(char), outLen1 + outLen2, ofp);

    //cleanup
    free(indata);
    free(outdata);
}

int listDir(BIO *bio)
{
    char filename[128];
    int len;
    do
    {
	len = BIO_read(bio, filename, sizeof(filename));
	filename[len] = 0;
	if (filename[0] == 'b')
	{
	    break;
	}
	printf("%s", filename + 1);

    } while (filename[0] == 'l');

    return 1;
}

int fileDownload(BIO *bio, char *ifn)
{
    char ofn[128], rbuf[1024]; 
    FILE *ifp, *ofp;
    int len;
    
    
    strcpy(ofn, ifn);
    printf("downloading.. ");
    fflush(stdout);

    //save location uses ext .aes for the encrypted file
    ifp = fopen(strcat(ifn, ".aes"), "wb+");
    if (!ifp)
    {
	printf("%s ", strerror(errno));
	return -1;
    }

    //downloading file
    do
    {
	if ((len = BIO_read(bio, rbuf, sizeof(rbuf))) <= 0)
	   return -1;
	fwrite(rbuf + 1, 1, len - 2, ifp);
    } while (rbuf[0] == 'u');

    printf("done\ndecrypting.. ");
    
    //decrpyting
    fseek(ifp, 0L, SEEK_SET);
    ofp = fopen(ofn, "wb");
    decrypt(ifp, ofp);

    printf("done\n\n");

    //cleanup
    fclose(ifp);
    fclose(ofp);
    remove(ifn);

    return 1;
}


void fileUpload(BIO *bio, char *ifn)
{
    char buf[1024] = "u", ofn[128], done[4] = "b\n";
    FILE *ifp, *ofp;
    int len;

    printf("encrypting.. ");
    fflush(stdout);
    
    //encrypt file
    ifp = fopen(ifn, "rb");
    if (!ifp)
    {
	printf("%s\n", strerror(errno));
	return;
    }
    
    strcpy(ofn, ifn);
    ofp = fopen(strcat(ofn, ".aes"), "wb+");
    encrypt(ifp, ofp);
    
    printf("done\n");
    
    fseek(ofp, 0L, SEEK_SET);

    printf("uploading.. ");
    fflush(stdout);
    
    //upload file
    while ((len = fread(buf + 1, 1, 1020, ofp)) == 1020)
    {
	BIO_write(bio, buf, len + 2);
    }

    if (len > 0 && len != 1020)
    {
	buf[len + 1] = '\n';
	BIO_write(bio, buf, len + 2);
    }

    printf("done\n\n");

    //cleanup
    fclose(ofp);
    fclose(ifp);
    remove(ofn);

    BIO_write(bio, done, strlen(done));
}

int handleU(BIO *bio)
{
    char *filename;
    char fn[128] = "";
    char done[4] = "b\n";
    int serr;

    //remove error messages
    serr = dup(2);
    freopen("/dev/null", "w", stderr);

    filename = (char *)tinyfd_openFileDialog("select file", "", 0, NULL, NULL, 0);

    //restore error messages
    dup2(serr, 2);
    close(serr);

    if (filename == NULL)
    {
	BIO_write(bio, done, strlen(done));
	return 0;
    }

    printf("\nfile: %s\n", filename);

    //sending file name
    strcpy(fn, strrchr(filename, '/'));
    fn[0] = 'u';
    BIO_write(bio, fn, strlen(fn));

    //uploading
    fileUpload(bio, filename);

    return 1;
}

int handleD(BIO *bio)
{
    char rbuf[128], wbuf[128];
    char bk[4] = "b\n";
    char dl[4] = "d\n";
    char *fn;
    int len, serr, ret;

    while (1)
    {
	listDir(bio);
	len = BIO_read(bio, rbuf, sizeof(rbuf));
	rbuf[len] = 0;
	printf("%s", rbuf);
	printf("> ");
	
	fgets(wbuf, sizeof(wbuf), stdin);
	printf("\nfile: %s", wbuf);
	BIO_write(bio, wbuf, sizeof(wbuf));

	len = BIO_read(bio, rbuf, sizeof(rbuf));
	rbuf[len] = 0;
	if (rbuf[0] == 'o')
	{
	    printf("%s", rbuf);
	    return 1;
	} else if (rbuf[0] == 'e')
	{
	    printf("%s", rbuf);
	    continue;
	}

	wbuf[strlen(wbuf) - 1] = 0;

	serr = dup(2);
	freopen("/dev/null", "w", stderr);

	//save location
	fn = (char *)tinyfd_saveFileDialog("save location", wbuf, 0, NULL, NULL);

	//restore error messages
	dup2(serr, 2);
	close(serr);

	if (fn == NULL)
	{
	    BIO_write(bio, bk, strlen(bk));
	    continue;
	}
	BIO_write(bio, dl, strlen(dl));

	break;
    }
    ret = fileDownload(bio, fn);
    if (ret < 0)
	return ret;
    len = BIO_read(bio, rbuf, sizeof(rbuf));
    rbuf[len] = 0;
    printf("%s", rbuf);
    return 1;
}

int handleR(BIO *bio)
{
    int len;
    char rbuf[128], wbuf[128];
    while (1)
    {
	listDir(bio);

	len = BIO_read(bio, rbuf, sizeof(rbuf));
	rbuf[len] = 0;
	printf("%s", rbuf);
	printf("> ");
	
	fgets(wbuf, sizeof(wbuf), stdin);
	printf("\n");
	BIO_write(bio, wbuf, sizeof(wbuf));

	len = BIO_read(bio, rbuf, sizeof(rbuf));
	rbuf[len] = 0;
	if (rbuf[0] == 'o')
	{
	    printf("%s", rbuf);
	    return 1;
	} else if (rbuf[0] == 'e')
	{
	    printf("%s", rbuf);
	    continue;
	}
	wbuf[strlen(wbuf) - 1] = 0;
	printf("removing %s.. ", wbuf);
	fflush(stdout);
	len = BIO_read(bio, rbuf, sizeof(rbuf));
	rbuf[len] = 0;
	printf("done\n\n%s", rbuf);
    }
}

int handle(BIO *bio, char c)
{
    switch(c)
    {
	case 'q':   //done
	    return -1;
	case 'd':   //done
	    return handleD(bio);
	case 'u':   //done
	    return handleU(bio);
	case 'r':
	    return handleR(bio);
	case 'l':   //done
	    return listDir(bio);
	case 'o':   //done
	    return 1;
	default:    //done
	    return 1;
    }
}

int main(int argc, char *argv[])
{
    char rbuf[1024], wbuf[1024];
    SSL_CTX *context;
    BIO *sslbio;
    SSL *ssl;
    int len;

    if (argc != 2)
    {
	printf("usage: %s <hostname:port>\n", argv[0]);
	exit(1);
    }

    //initialize ssl library
    SSL_library_init();

    //crypto algorithms and error messages
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();


    //create client context
    context = SSL_CTX_new(TLSv1_2_client_method()); /* TLS v1.2 */
    if (context == NULL)
    {
	ERR_print_errors_fp(stderr);
	abort();
    }
    initCTX(context);

    //initialize BIO connection
    sslbio = BIO_new_ssl_connect(context);
    BIO_set_conn_hostname(sslbio, argv[1]);

    //get back ssl state
    BIO_get_ssl(sslbio, &ssl);

    //Attempt connection
    if (BIO_do_connect(sslbio) <= 0)
    {
	fprintf(stderr, "connect error");
	ERR_print_errors_fp(stderr);
	abort();
    }

    //TLS handshake
    if (BIO_do_handshake(sslbio) <= 0)
    {
	fprintf(stderr, "handshake error");
	ERR_print_errors_fp(stderr);
	abort();
    }

    //TLS connection
    printf("Connected with %s encryption\n", SSL_get_cipher(ssl));
    len = BIO_read(sslbio, rbuf, sizeof(rbuf));
    rbuf[len] = 0;
    printf("%s", rbuf);
    do
    {
	printf("> ");
	fgets(wbuf, sizeof(wbuf), stdin);
	printf("\n");
	BIO_write(sslbio, wbuf, sizeof(wbuf));
	len = BIO_read(sslbio, rbuf, sizeof(rbuf));
	if (len <= 0)
	    break;
	rbuf[len] = 0;
	printf("%s", rbuf);

    } while (handle(sslbio, rbuf[0]) >= 0);

    //clean up
    SSL_free(ssl);
    SSL_CTX_free(context);
    EVP_cleanup();
}
