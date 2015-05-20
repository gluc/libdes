#ifndef __RLIBDES_H__
#define __RLIBDES_H__

#define RLIBDES_ENCRYPT		0x00000001     // encrypt if set, else decrypt 
#define RLIBDES_SUNOS_COMPAT	0x00000002 // enable/disable SUNOS compatibility 
#define RLIBDES_CBC_CHECKSUM	0x00000004 // calculate cbc-checksum or not 
#define RLIBDES_KEY_FMT_HEX	0x00000008 // if key string is in hex instead of b64 
#define RLIBDES_3DES		0x00000010 // set to use 3DES 
#define RLIBDES_MODE_ECB	0x00000020 // if set, then encryption mode is ECB, if not - CBC 
#define RLIBDES_UUENC_ENCRYPTED	0x00000040 // set if encrypted data is\should be uuencoded (uuencHeaderFile must be set)

int callRDES( unsigned int *flags, char  **key, char  **inFile, char **outFile, char **cbcChecksumOutFile, char **uuencHeaderFile );

SEXP rdesEncrypt( SEXP key, SEXP data );
SEXP rdesDecrypt( SEXP key, SEXP encrypted );

#endif
