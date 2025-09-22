/***********************************************************************

   File          : cse543-proto.c

   Description   : This is the network interfaces for the network protocol connection.


***********************************************************************/

/* Include Files */
#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <errno.h>
#include <assert.h>
#include <unistd.h>
#include <string.h>
#include <sys/select.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <inttypes.h>
#include <stdint.h>

/* OpenSSL Include Files */
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/rand.h>

/* Project Include Files */
#include "cse543-util.h"
#include "cse543-network.h"
#include "cse543-proto.h"
#include "cse543-ssl.h"

/* Functional Prototypes */

/**********************************************************************

    Function    : make_req_struct
    Description : build structure for request from input
    Inputs      : rptr - point to request struct - to be created
                  filename - filename
                  cmd - command string (small integer value)
                  type - - command type (small integer value)
    Outputs     : 0 if successful, -1 if failure

***********************************************************************/

int make_req_struct( struct rm_cmd **rptr, char *filename, char *cmd, char *type )
{
	struct rm_cmd *r;
	int rsize;
	int len; 

	assert(rptr != 0);
	assert(filename != 0);
	len = strlen( filename );

	rsize = sizeof(struct rm_cmd) + len;
	*rptr = r = (struct rm_cmd *) malloc( rsize );
	memset( r, 0, rsize );
	
	r->len = len;
	memcpy( r->fname, filename, r->len );  
	r->cmd = atoi( cmd );
	r->type = atoi( type );

	return 0;
}


/**********************************************************************

    Function    : get_message
    Description : receive data from the socket
    Inputs      : sock - server socket
                  hdr - the header structure
                  block - the block to read
    Outputs     : bytes read if successful, -1 if failure

***********************************************************************/

int get_message( int sock, ProtoMessageHdr *hdr, char *block )
{
	/* Read the message header */
	recv_data( sock, (char *)hdr, sizeof(ProtoMessageHdr), 
		   sizeof(ProtoMessageHdr) );
	hdr->length = ntohs(hdr->length);
	assert( hdr->length<MAX_BLOCK_SIZE );
	hdr->msgtype = ntohs( hdr->msgtype );
	if ( hdr->length > 0 )
		return( recv_data( sock, block, hdr->length, hdr->length ) );
	return( 0 );
}

/**********************************************************************

    Function    : wait_message
    Description : wait for specific message type from the socket
    Inputs      : sock - server socket
                  hdr - the header structure
                  block - the block to read
                  my - the message to wait for
    Outputs     : bytes read if successful, -1 if failure

***********************************************************************/

int wait_message( int sock, ProtoMessageHdr *hdr, 
                 char *block, ProtoMessageType mt )
{
	/* Wait for init message */
	int ret = get_message( sock, hdr, block );
	if ( hdr->msgtype != mt )
	{
		/* Complain, explain, and exit */
		char msg[128];
		sprintf( msg, "Server unable to process message type [%d != %d]\n", 
			 hdr->msgtype, mt );
		errorMessage( msg );
		exit( -1 );
	}

	/* Return succesfully */
	return( ret );
}

/**********************************************************************

    Function    : send_message
    Description : send data over the socket
    Inputs      : sock - server socket
                  hdr - the header structure
                  block - the block to send
    Outputs     : bytes read if successful, -1 if failure

***********************************************************************/

int send_message( int sock, ProtoMessageHdr *hdr, char *block )
{
     int real_len = 0;

     /* Convert to the network format */
     real_len = hdr->length;
     hdr->msgtype = htons( hdr->msgtype );
     hdr->length = htons( hdr->length );
     if ( block == NULL )
          return( send_data( sock, (char *)hdr, sizeof(hdr) ) );
     else 
          return( send_data(sock, (char *)hdr, sizeof(hdr)) ||
                  send_data(sock, block, real_len) );
}

/**********************************************************************

    Function    : encrypt_message
    Description : Get message encrypted (by encrypt) and put ciphertext 
                   and metadata for decryption into buffer
    Inputs      : plaintext - message
                : plaintext_len - size of message
                : key - symmetric key
                : buffer - place to put ciphertext and metadata for 
                   decryption on other end
                : len - length of the buffer after message is set 
    Outputs     : 0 if successful, -1 if failure

***********************************************************************/
/*** YOUR CODE ***/
int encrypt_message( unsigned char *plaintext, unsigned int plaintext_len, unsigned char *key, 
		     unsigned char *buffer, unsigned int *len )
{
	/*
	* Given plaintext, its length plaintext_len and key
	* Encrypt it using the key and copy the resulting encrypted data into buffer
	*/

	/*
	* Encrypted Buffer :- a Tag + an IV + Cipher Text
	*/

	/*
	* Take inspiration from Test AES function - We are trying to employ Symmetric Key Cryptography here
	*/

	int iv_len = 16;
	int tag_len = TAGSIZE;
	int ciphertext_len = plaintext_len;

	unsigned char* iv = malloc(iv_len);
	unsigned char* tag = malloc(tag_len);
	unsigned char* ciphertext = malloc(ciphertext_len);
	if (!iv || !tag || !ciphertext) {
		errorMessage("encrypt_message: Malloc Failure. \n");
		free(iv);
		free(tag);
        free(ciphertext);
		return -1;
	}

	int err_generate_pseudorandom_bytes = 0;
	err_generate_pseudorandom_bytes = generate_pseudorandom_bytes(iv, iv_len);
	if(err_generate_pseudorandom_bytes != 0) { 
		errorMessage("encrypt_message: generate_pseudorandom_bytes() failed to generate IV. \n");
		free(iv);
        free(tag);
        free(ciphertext);
        return -1;
	}
	
	// Encryption
	ciphertext_len = encrypt(plaintext, plaintext_len, (unsigned char *)NULL, 0, key, iv, ciphertext, tag);
	if(ciphertext_len < 0) {
		errorMessage("encrypt_message: encrypt() failed. \n");
		free(iv);
		free(tag);
		free(ciphertext);

		return -1;
	}

	// Copy onto Buffer
	*len = iv_len + tag_len + ciphertext_len;
	memcpy(buffer, iv, iv_len);
	memcpy(buffer + iv_len, tag, tag_len);
	memcpy(buffer + iv_len + tag_len, ciphertext, ciphertext_len);

	free(iv);
	free(tag);
	free(ciphertext);

	return 0;
}



/**********************************************************************

    Function    : decrypt_message
    Description : Produce plaintext for given ciphertext buffer (ciphertext+tag) using key 
    Inputs      : buffer - encrypted message - includes tag
                : len - length of encrypted message and tag
                : key - symmetric key
                : plaintext - message
                : plaintext_len - size of message
    Outputs     : 0 if successful, -1 if failure

***********************************************************************/
/*** YOUR CODE ***/
int decrypt_message( unsigned char *buffer, unsigned int len, unsigned char *key, 
		     unsigned char *plaintext, unsigned int *plaintext_len )
{
	/*
	* Given buffer, its length len and key
	* Decrypt it using the key and copy the resulting data into plaintext, its length into plaintext_len
	*/

	/*
	* Take inspiration from Test AES function - We are trying to employ Symmetric Key Cryptography here
	*/

	int iv_len = 16;
	int tag_len = TAGSIZE;

	if (len < iv_len + tag_len) {
        errorMessage("decrypt_message: Invalid Buffer.\n");
        return -1;
    }

	int ciphertext_len = len - tag_len - iv_len;

	// The buffer is designed as IV + Tag + CipherText. 
	// We will need to seperate the ciphertext from tag and IV
	// I have taken pointers here to track the ciphertext
	unsigned char* iv = buffer;
	unsigned char* tag = buffer + iv_len;
	unsigned char* ciphertext = buffer + iv_len + tag_len;


	int decrypt_status = -1;
	decrypt_status = decrypt( ciphertext, ciphertext_len, (unsigned char *) NULL, 0, tag, key, iv, plaintext );	
	if(decrypt_status < 0) {
		errorMessage("decrypt_message: decrypt() failed. Invalid key/tag. \n");
		return -1;
	}

	*plaintext_len = (unsigned int)decrypt_status;

	return 0;
}



/**********************************************************************

    Function    : extract_public_key
    Description : Create public key data structure from network message
    Inputs      : buffer - network message  buffer
                : size - size of buffer
                : pubkey - public key pointer
    Outputs     : 0 if successful, -1 if failure

***********************************************************************/

int extract_public_key( char *buffer, unsigned int size, EVP_PKEY **pubkey )
{
	RSA *rsa_pubkey = NULL;
	FILE *fptr;

	*pubkey = EVP_PKEY_new();

	/* Extract server's public key */
	/* Make a function */
	fptr = fopen( PUBKEY_FILE, "w+" );

	if ( fptr == NULL ) {
		errorMessage("Failed to open file to write public key data");
		return -1;
	}

	fwrite( buffer, size, 1, fptr );
	rewind(fptr);

	/* open public key file */
	if (!PEM_read_RSAPublicKey( fptr, &rsa_pubkey, NULL, NULL))
	{
		errorMessage("Cliet: Error loading RSA Public Key File.\n");
		return -1;
	}

	if (!EVP_PKEY_assign_RSA(*pubkey, rsa_pubkey))
	{
		errorMessage("Client: EVP_PKEY_assign_RSA: failed.\n");
		return -1;
	}

	fclose( fptr );
	return 0;
}


/**********************************************************************

    Function    : generate_pseudorandom_bytes
    Description : Generate pseudirandom bytes using OpenSSL PRNG 
    Inputs      : buffer - buffer to fill
                  size - number of bytes to get
    Outputs     : 0 if successful, -1 if failure

***********************************************************************/

int generate_pseudorandom_bytes( unsigned char *buffer, unsigned int size)
{
	if(buffer == NULL || size == 0) {
		errorMessage("generate_pseudorandom_bytes: Invalid input.\n");
		return -1;
	}

	int rand_bytes_status = 1;
	rand_bytes_status = RAND_bytes(buffer, size);

	if(rand_bytes_status != 1) {
		errorMessage("generate_pseudorandom_bytes: Error in RAND_bytes.\n");
		return -1;
	}
	return 0;
}


/**********************************************************************

    Function    : seal_symmetric_key
    Description : Encrypt symmetric key using public key
    Inputs      : key - symmetric key
                  keylen - symmetric key length in bytes
                  pubkey - public key
                  buffer - output buffer to store the encrypted seal key and ciphertext (iv?)
    Outputs     : len if successful, -1 if failure

***********************************************************************/
/*** YOUR CODE ***/
int seal_symmetric_key( unsigned char *key, unsigned int keylen, EVP_PKEY *pubkey, char *buffer )
{
	/*
	* Given symmetric key "key", its length keylen and a known public key "pubkey"
	* Encrypt the key using the RSA pubkey and copy the resulting encrypted data into buffer
	*/

	/*
	* The Encrypted Buffer needs the following - Encrypted RSA pubkey, its length, an IV, its length, Ciphertext of Symmetric Key, its length
	* One Such implementation is :- encypted rsa pubkey length + iv length + ciphertext length + encrypted rsa pubkey + IV + Ciphertext
	*/

	/*
	* Take inspiration from Test RSA function - We are trying to employ Asymmetric Key Cryptography here
	*/

	int ciphertext_len = 0;
	unsigned char *ciphertext;
	unsigned char *ek;
	unsigned int ekl; 
	unsigned char *iv;
	unsigned int ivl;
	unsigned int buffer_len = 0;

	ciphertext_len = rsa_encrypt( key, keylen, &ciphertext, &ek, &ekl, &iv, &ivl, pubkey );
	if(ciphertext_len < 0) {
		errorMessage("seal_symmetric_key: rsa_encrypt failed.\n");
		return -1;
	}

	memcpy(buffer, &ekl, sizeof(ekl));
	memcpy(buffer + sizeof(ekl), &ivl, sizeof(ivl));
	memcpy(buffer + sizeof(ekl) + sizeof(ivl), &ciphertext_len, sizeof(ciphertext_len));
	memcpy(buffer + sizeof(ekl) + sizeof(ivl) + sizeof(ciphertext_len), ek, ekl);
	memcpy(buffer + sizeof(ekl) + sizeof(ivl) + sizeof(ciphertext_len) + ekl, iv, ivl);
	memcpy(buffer + sizeof(ekl) + sizeof(ivl) + sizeof(ciphertext_len) + ekl + ivl, ciphertext, ciphertext_len);

	free(ek);
	free(iv);
	free(ciphertext);

	buffer_len = sizeof(ekl) + sizeof(ivl) + sizeof(ciphertext_len) + ekl + ivl + ciphertext_len;

	return buffer_len;
}

/**********************************************************************

    Function    : unseal_symmetric_key
    Description : Perform SSL unseal (open) operation to obtain the symmetric key
    Inputs      : buffer - buffer of crypto data for decryption (ek, iv, ciphertext)
                  len - length of buffer
                  pubkey - public key 
                  key - symmetric key (plaintext from unseal)
    Outputs     : 0 if successful, -1 if failure

***********************************************************************/
/*** YOUR CODE ***/
int unseal_symmetric_key( char *buffer, unsigned int len, EVP_PKEY *privkey, unsigned char **key )
{
	/*
	* Given buffer, its length len and a known private key "privkey"
	* Decrypt it using the private key and copy the resulting data into key
	*/

	/*
	* Remember : The buffer could be something like this ("encypted rsa pubkey length + iv length + ciphertext length + encrypted rsa pubkey + IV + Ciphertext")
	*/

	/*
	* Take inspiration from Test RSA function - We are trying to employ Asymmetric Key Cryptography here
	*/

	unsigned int ekl, ivl, ciphertext_len;

	unsigned int header_len = sizeof(ekl) + sizeof(ivl) + sizeof(ciphertext_len);
    if (len < header_len) {
        errorMessage("unseal_symmetric_key: Buffer is too small to be valid.\n");
        return -1;
    }

	memcpy(&ekl, buffer, sizeof(ekl));
	memcpy(&ivl, buffer + sizeof(ekl), sizeof(ivl));
	memcpy(&ciphertext_len, buffer + sizeof(ekl) + sizeof(ivl), sizeof(ciphertext_len));

	if (header_len + ekl + ivl + ciphertext_len != len) {
        errorMessage("unseal_symmetric_key: Buffer corruption or invalid length fields.\n");
        return -1;
    }

	unsigned char* ek = buffer + sizeof(ekl) + sizeof(ivl) + sizeof(ciphertext_len);
	unsigned char* iv = buffer + sizeof(ekl) + sizeof(ivl) + sizeof(ciphertext_len) + ekl;
	unsigned char* ciphertext = buffer + sizeof(ekl) + sizeof(ivl) + sizeof(ciphertext_len) + ekl + ivl;

	int asymm_decryption_status = 0;

 	asymm_decryption_status = rsa_decrypt(ciphertext, ciphertext_len, ek, ekl, iv, ivl, key, privkey);
    if (asymm_decryption_status < 0) {
        errorMessage("unseal_symmetric_key: rsa_decrypt failed.\n");
        return -1;
    }

	return 0;
}


/* 

  CLIENT FUNCTIONS 

*/



/**********************************************************************

    Function    : client_authenticate
    Description : this is the client side of the exchange
    Inputs      : sock - server socket
                  session_key - the key resulting from the exchange
    Outputs     : bytes read if successful, -1 if failure

***********************************************************************/
/*** YOUR CODE ***/
int client_authenticate( int sock, unsigned char **session_key )
{
	/*
	* Send Message to server with header CLIENT_INIT_EXCHANGE
	*/

	ProtoMessageHdr header;
	header.msgtype = CLIENT_INIT_EXCHANGE;
	header.length = 0;

	int client_send_status = 0;
	client_send_status = send_message(sock, &header, NULL);
	if(client_send_status != 0) {
		errorMessage("client_authenticate: Client message send failed for CLIENT_INIT_EXCHANGE.\n");
		return -1;
	}

	/*
	* Wait for Message from server with header SERVER_INIT_RESPONSE
	* Extract Pub Key out of the message -> Create a new Symmetric Key -> Encrypt it using the Pub Key of server
	*/

	char server_message_buffer[MAX_BLOCK_SIZE];
	int server_wait_msg_status = 0;
	server_wait_msg_status = wait_message(sock, &header, server_message_buffer, SERVER_INIT_RESPONSE);
	if(server_wait_msg_status < 0) {
		errorMessage("client_authenticate: Server message wait failed for SERVER_INIT_RESPONSE.\n");
		return -1;
	}

	unsigned char *key_to_seal = NULL;
	key_to_seal = (unsigned char *) malloc (KEYSIZE);
	if(key_to_seal == NULL) {
		errorMessage("client_authenticate: Malloc failure for symmetric key");
		free(key_to_seal);
		return -1;
	}

	int generate_session_key_status = 0;
	generate_session_key_status = generate_pseudorandom_bytes(key_to_seal, KEYSIZE);
	if (generate_session_key_status != 0) {
        errorMessage("client_authenticate: Failed to generate session key\n");
		free(key_to_seal);
		return -1;
    }

	EVP_PKEY *server_pubkey = EVP_PKEY_new();
	int extract_public_key_status = 0;
	extract_public_key_status = extract_public_key(server_message_buffer, header.length, &server_pubkey);
	if(extract_public_key_status != 0) {
		errorMessage("client_authenticate: Failed to extract server public key\n");
		free(key_to_seal);
		EVP_PKEY_free(server_pubkey);
		return -1;
	}

	char encrypted_key_body[MAX_BLOCK_SIZE];
	int encrypted_key_body_len = 0;
	encrypted_key_body_len = seal_symmetric_key(key_to_seal, KEYSIZE, server_pubkey, encrypted_key_body);
    if (encrypted_key_body_len < 0) {
        errorMessage("client_authenticate: Failed to seal symmetric key\n");
		free(key_to_seal);
		EVP_PKEY_free(server_pubkey);
		return -1;
    }

	/*
	* Send message to server with header CLIENT_INIT_ACK
	* The encrypted symmetric key from previous phase should be sent here
	*/

	header.msgtype = CLIENT_INIT_ACK;
	header.length = encrypted_key_body_len;
	int client_ack_send_status = 0;
	client_ack_send_status = send_message(sock, &header, encrypted_key_body);
	if(client_ack_send_status != 0) {
		errorMessage("client_authenticate: Client message send failed for CLIENT_INIT_ACK\n");
		free(key_to_seal);
		EVP_PKEY_free(server_pubkey);
		return -1;
	}

	/*
	* Wait message from server with header SERVER_INIT_ACK
	* Decrypt the message using the symmetric key and make sure the code doesn't break. 
	* This would mean both Client and Server have the same symmetric key now and the SSH connection is successful
	*/

	int server_ack_status = 0;
	server_ack_status = wait_message(sock, &header, NULL, SERVER_INIT_ACK);
	if(server_ack_status < 0) {
		errorMessage("client_authenticate: Server response invalid for SERVER_INIT_ACK.\n");
		free(key_to_seal);
		EVP_PKEY_free(server_pubkey);
		return -1;
	}

	/*
	* Store the Symmetric key in session_key for later use. 
	*/

	*session_key = key_to_seal;
	return 0;
}

/**********************************************************************

    Function    : transfer_file
    Description : transfer the entire file over the wire
    Inputs      : r - rm_cmd describing what to transfer and do
                  fname - the name of the file
                  sz - this is the size of the file to be read
                  key - the cipher to encrypt the data with
    Outputs     : 0 if successful, -1 if failure

***********************************************************************/

int transfer_file( struct rm_cmd *r, char *fname, int sock, 
		   unsigned char *key )
{
	/* Local variables */
	int readBytes = 1, totalBytes = 0, fh;
	unsigned int outbytes;
	ProtoMessageHdr hdr;
	char block[MAX_BLOCK_SIZE];
	char outblock[MAX_BLOCK_SIZE];

	/* Read the next block */
	printf ("\n\nfile name: %s\n\n", fname);
	if ( (fh=open(fname, O_RDONLY, 0)) == -1 )
	{
		/* Complain, explain, and exit */
		char msg[128];
		sprintf( msg, "failure opening file [%.64s]\n", fname );
		errorMessage( msg );
		exit( -1 );
	}

	/* Send the command */
	hdr.msgtype = FILE_XFER_INIT;
	hdr.length = sizeof(struct rm_cmd) + r->len;
	send_message( sock, &hdr, (char *)r );

	/* Start transferring data */
	while ( (r->cmd == CMD_CREATE) && (readBytes != 0) )
	{
		/* Read the next block */
		if ( (readBytes=read( fh, block, BLOCKSIZE )) == -1 )
		{
			/* Complain, explain, and exit */
			errorMessage( "failed read on data file.\n" );
			exit( -1 );
		}
		
		/* A little bookkeeping */
		totalBytes += readBytes;
		printf( "Reading %10d bytes ...\r", totalBytes );

		/* Send data if needed */
		if ( readBytes > 0 ) 
		{
#if 1
			printf("Block is:\n");
			BIO_dump_fp (stdout, (const char *)block, readBytes);
#endif

			/* Encrypt and send */
			encrypt_message( (unsigned char *)block, readBytes, key, 
					 (unsigned char *)outblock, &outbytes );
			hdr.msgtype = FILE_XFER_BLOCK;
			hdr.length = outbytes;
			send_message( sock, &hdr, outblock );
		}
	}

	/* Send the ack, wait for server ack */
	hdr.msgtype = EXIT;
	hdr.length = 0;
	send_message( sock, &hdr, NULL );
	wait_message( sock, &hdr, block, EXIT );

	/* Clean up the file, return successfully */
	close( fh );
	return( 0 );
}


/**********************************************************************

    Function    : client_secure_transfer
    Description : this is the main function to execute the protocol
    Inputs      : r - cmd describing what to transfer and do
                  fname - filename of the file to transfer
                  address - address of the server
    Outputs     : 0 if successful, -1 if failure

***********************************************************************/
/*** YOUR_CODE ***/
int client_secure_transfer( struct rm_cmd *r, char *fname, char *address ) 
{
	/*
		Executes a secure client-side file transfer by connecting to the server, authenticating, and sending the file using symmetric key encryption.
	*/

	/* Connect to the server using the provided address */
	int sock;
	unsigned char* session_key = NULL;
	sock = client_connect(address);
    if (sock < 0) {
        errorMessage("client_secure_transfer: Connection to server failed.\n");
        return -1;
    }

    /* Perform client authentication and establish a session key */
	int client_authenticate_status = 0;
	client_authenticate_status = client_authenticate(sock, &session_key);
	if(client_authenticate_status != 0) {
		errorMessage("client_secure_transfer: Client authentication failed.\n");
		close(sock);
		return -1;
	}

    /* Transfer the file securely using the established symmetric key */
	int transfer_file_status = 0;
	transfer_file_status = transfer_file(r, fname, sock, session_key);
	if(transfer_file_status != 0) {
		errorMessage("client_secure_transfer: File transfer failed.\n");
		close(sock);
		return -1;
	}

    /* Close the connection */
	close(sock);
	free(session_key);

    /* Return status (0 on success, -1 on failure) */
	return 0;
}

/* 

  SERVER FUNCTIONS 

*/

/**********************************************************************

    Function    : test_rsa
    Description : test the rsa encrypt and decrypt
    Inputs      : 
    Outputs     : 0

***********************************************************************/

int test_rsa( EVP_PKEY *privkey, EVP_PKEY *pubkey )
{
	unsigned int len = 0;
	unsigned char *ciphertext;
	unsigned char *plaintext;
	unsigned char *ek;
	unsigned int ekl; 
	unsigned char *iv;
	unsigned int ivl;

	printf("*** Test RSA encrypt and decrypt. ***\n");

	len = rsa_encrypt( (unsigned char *)"help me, mr. wizard!", 20, &ciphertext, &ek, &ekl, &iv, &ivl, pubkey );

#if 1
	printf("Ciphertext is:\n");
	BIO_dump_fp (stdout, (const char *)ciphertext, len);
#endif

	len = rsa_decrypt( ciphertext, len, ek, ekl, iv, ivl, &plaintext, privkey );

	printf("Msg: %s\n", plaintext );
    
	return 0;
}


/**********************************************************************

    Function    : test_aes
    Description : test the aes encrypt and decrypt
    Inputs      : 
    Outputs     : 0

***********************************************************************/

int test_aes( )
{
	int rc = 0;
	unsigned char *key;
	unsigned char *ciphertext, *tag;
	unsigned char *plaintext;
	unsigned char *iv = (unsigned char *)"0123456789012345";
	int clen = 0, plen = 0;
	unsigned char msg[] = "Help me, Mr. Wizard!";
	unsigned int len = strlen((char *)msg);

	printf("*** Test AES encrypt and decrypt. ***\n");

	/* make key */
	key= (unsigned char *)malloc( KEYSIZE );
	rc = generate_pseudorandom_bytes( key, KEYSIZE );	
	assert( rc == 0 );

	/* perform encrypt */
	ciphertext = (unsigned char *)malloc( len );
	tag = (unsigned char *)malloc( TAGSIZE );
	clen = encrypt( msg, len, (unsigned char *)NULL, 0, key, iv, ciphertext, tag);
	assert(( clen > 0 ) && ( clen <= len ));

#if 1
	printf("Ciphertext is:\n");
	BIO_dump_fp (stdout, (const char *)ciphertext, clen);
	
	printf("Tag is:\n");
	BIO_dump_fp (stdout, (const char *)tag, TAGSIZE);
#endif

	/* perform decrypt */
	plaintext = (unsigned char *)malloc( clen+TAGSIZE );
	memset( plaintext, 0, clen+TAGSIZE ); 
	plen = decrypt( ciphertext, clen, (unsigned char *) NULL, 0, 
		       tag, key, iv, plaintext );
	assert( plen > 0 );

	/* Show the decrypted text */
#if 0
	printf("Decrypted text is: \n");
	BIO_dump_fp (stdout, (const char *)plaintext, (int)plen);
#endif
	
	printf("Msg: %s\n", plaintext );
    
	return 0;
}


/**********************************************************************

    Function    : server_protocol
    Description : server processing of crypto protocol
    Inputs      : sock - server socket
                  key - the key resulting from the protocol
    Outputs     : bytes read if successful, -1 if failure

***********************************************************************/
/*** YOUR_CODE ***/
int server_protocol( int sock, char *pubfile, EVP_PKEY *privkey, unsigned char **enckey )
{
	/*
	* Counterparts of client actions that the server needs to take.
	*/

	// Server waiting for Client Init
	char client_message_buffer[MAX_BLOCK_SIZE];
	ProtoMessageHdr header;
	int client_wait_status = 0;
	client_wait_status = wait_message(sock, &header, client_message_buffer, CLIENT_INIT_EXCHANGE);
	if(client_wait_status < 0) {
		errorMessage("client_authenticate: Client message wait failed for CLIENT_INIT_EXCHANGE.\n");
		return -1;
	}

	// Copying Server's Public key to the buffer
	// I have referred to extract_public_key for this
	FILE *fptr;
	fptr = fopen(pubfile, "r");
	if(fptr == NULL) {
		errorMessage("server_protocol: Cannot open public key.\n");
		return -1;
	}
	fseek(fptr, 0, SEEK_END);
	long long int pubkey_len;
    pubkey_len = ftell(fptr);
    rewind(fptr);
    if (pubkey_len >= MAX_BLOCK_SIZE) {
        errorMessage("server_protocol: Public key is too large.\n");
        fclose(fptr);
        return -1;
    }
    fread(client_message_buffer, pubkey_len, 1, fptr);
    fclose(fptr);

	// Sending Server Public key
	header.msgtype = SERVER_INIT_RESPONSE;
	header.length = pubkey_len;
	int server_send_init_status = 0;
	server_send_init_status = send_message(sock, &header, client_message_buffer);
	if(server_send_init_status < 0) {
		errorMessage("server_protocol: Server message send failed for SERVER_INIT_RESPONSE.\n");
		return -1;
	}

	// Waiting for Client's Session Key
	int server_wait_sessionkey_status = 0;
	server_wait_sessionkey_status = wait_message(sock, &header, client_message_buffer, CLIENT_INIT_ACK);
	if(server_wait_sessionkey_status < 0) {
		errorMessage("server_protocol: Client message wait failed for CLIENT_INIT_ACK.\n");
		return -1;
	}

	// Decrypting Client's key
	int session_key_decrypt_status = 0;
	session_key_decrypt_status = unseal_symmetric_key(client_message_buffer, header.length, privkey, enckey);
	if (session_key_decrypt_status != 0) {
        errorMessage("server_protocol: Session Key decryption failed.\n");
        return -1;
    }

	// Send ACK to client
	header.msgtype = SERVER_INIT_ACK;
	header.length = 0;
	int server_send_ack_status = 0;
	server_send_ack_status = send_message(sock, &header, NULL);
	if(server_send_ack_status != 0) {
		errorMessage("server_protocol: Server message send failed for SERVER_INIT_ACK.\n");
		if (*enckey != NULL) {
            free(*enckey);
            *enckey = NULL;
        }
		return -1;
	}

	return 0;
}


/**********************************************************************

    Function    : receive_file
    Description : receive a file over the wire
    Inputs      : sock - the socket to receive the file over
                  key - the cicpher used to encrypt the traffic
    Outputs     : 0 if successful, -1 if failure

***********************************************************************/

#define FILE_PREFIX "./shared/"

int receive_file( int sock, unsigned char *key ) 
{
	/* Local variables */
	unsigned long totalBytes = 0;
	int done = 0, fh = 0;
	unsigned int outbytes;
	ProtoMessageHdr hdr;
	struct rm_cmd *r = NULL;
	char block[MAX_BLOCK_SIZE];
	unsigned char plaintext[MAX_BLOCK_SIZE];
	char *fname = NULL;
	int rc = 0;

	/* clear */
	bzero(block, MAX_BLOCK_SIZE);

	/* Receive the init message */
	wait_message( sock, &hdr, block, FILE_XFER_INIT );

	/* set command structure */
	struct rm_cmd *tmp = (struct rm_cmd *)block;
	unsigned int len = tmp->len;
	r = (struct rm_cmd *)malloc( sizeof(struct rm_cmd) + len );
	r->cmd = tmp->cmd, r->type = tmp->type, r->len = len;
	memcpy( r->fname, tmp->fname, len );

	/* open file */
	if ( r->type == TYP_DATA_SHARED ) {
		unsigned int size = r->len + strlen(FILE_PREFIX) + 1;
		char *fname = (char *)malloc( size );
		snprintf( fname, size, "%s%.*s", FILE_PREFIX, (int) r->len, r->fname );
		if ( (fh=open( fname, O_WRONLY|O_CREAT|O_TRUNC, 0700)) > 0 );  // TJ: need to change this for students
		else assert( 0 );
	}
	else assert( 0 );

	/* read the file data, if it's a create */ 
	if ( r->cmd == CMD_CREATE ) {
		/* Repeat until the file is transferred */
		printf( "Receiving file [%s] ..\n", fname );
		while (!done)
		{
			/* Wait message, then check length */
			get_message( sock, &hdr, block );
			if ( hdr.msgtype == EXIT ) {
				done = 1;
				break;
			}
			else
			{
				/* Write the data file information */
				rc = decrypt_message( (unsigned char *)block, hdr.length, key, 
						      plaintext, &outbytes );
				assert( rc  == 0 );
				write( fh, plaintext, outbytes );

#if 1
				printf("Decrypted Block is:\n");
				BIO_dump_fp (stdout, (const char *)plaintext, outbytes);
#endif

				totalBytes += outbytes;
				printf( "Received/written %ld bytes ...\n", totalBytes );
			}
		}
		printf( "Total bytes [%ld].\n", totalBytes );
		/* Clean up the file, return successfully */
		close( fh );
	}
	else {
		printf( "Server: illegal command %d\n", r->cmd );
		//	     exit( -1 );
	}

	/* Server ack */
	hdr.msgtype = EXIT;
	hdr.length = 0;
	send_message( sock, &hdr, NULL );

	return( 0 );
}

/**********************************************************************

    Function    : server_secure_transfer
    Description : this is the main function to execute the protocol
    Inputs      : pubkey - public key of the server
    Outputs     : 0 if successful, -1 if failure

***********************************************************************/

int server_secure_transfer( char *privfile, char *pubfile )
{
	/* Local variables */
	int server, errored, newsock;
	RSA *rsa_privkey = NULL, *rsa_pubkey = NULL;
	RSA *pRSA = NULL;
	EVP_PKEY *privkey = EVP_PKEY_new(), *pubkey = EVP_PKEY_new();
	fd_set readfds;
	unsigned char *key;
	FILE *fptr;

	/* initialize */
	OpenSSL_add_all_algorithms();
	OpenSSL_add_all_ciphers();
	ERR_load_crypto_strings();

	/* Connect the server/setup */
	server = server_connect();
	errored = 0;

	/* open private key file */
	fptr = fopen( privfile, "r" );
	assert( fptr != NULL);
	if (!(pRSA = PEM_read_RSAPrivateKey( fptr, &rsa_privkey, NULL, NULL)))
	{
		errorMessage("Error loading RSA Private Key File.\n");

		return 2;
	}

	if (!EVP_PKEY_assign_RSA(privkey, rsa_privkey))
	{
		errorMessage("EVP_PKEY_assign_RSA: failed.\n");
		return 3;
	}
	fclose( fptr ); 

	/* open public key file */
	fptr = fopen( pubfile, "r" );
	assert( fptr != NULL);
	if (!PEM_read_RSAPublicKey( fptr , &rsa_pubkey, NULL, NULL))
	{
		errorMessage("Error loading RSA Public Key File.\n");
		return 2;
	}

	if (!EVP_PKEY_assign_RSA( pubkey, rsa_pubkey))
	{
		errorMessage("EVP_PKEY_assign_RSA: failed.\n");
		return 3;
	}
	fclose( fptr );

	// Test the RSA encryption and symmetric key encryption
	test_rsa( privkey, pubkey );
	test_aes();

	/* Repeat until the socket is closed */
	while ( !errored )
	{
		FD_ZERO( &readfds );
		FD_SET( server, &readfds );
		if ( select(server+1, &readfds, NULL, NULL, NULL) < 1 )
		{
			/* Complain, explain, and exit */
			char msg[128];
			sprintf( msg, "failure selecting server connection [%.64s]\n",
				 strerror(errno) );
			errorMessage( msg );
			errored = 1;
		}
		else
		{
			/* Accept the connect, receive the file, and return */
			if ( (newsock = server_accept(server)) != -1 )
			{
				/* Do the protocol, receive file, shutdown */
				server_protocol( newsock, pubfile, privkey, &key );
				receive_file( newsock, key );
				close( newsock );
			}
			else
			{
				/* Complain, explain, and exit */
				char msg[128];
				sprintf( msg, "failure accepting connection [%.64s]\n", 
					 strerror(errno) );
				errorMessage( msg );
				errored = 1;
			}
		}
	}

	/* Return successfully */
	return( 0 );
}

