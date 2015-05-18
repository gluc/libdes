/* crypto/des/des.c */
/* Copyright (C) 1995-1997 Eric Young (eay@mincom.oz.au)
 * All rights reserved.
 *
 * This package is an SSL implementation written
 * by Eric Young (eay@mincom.oz.au).
 * The implementation was written so as to conform with Netscapes SSL.
 * 
 * This library is free for commercial and non-commercial use as long as
 * the following conditions are aheared to.  The following conditions
 * apply to all code found in this distribution, be it the RC4, RSA,
 * lhash, DES, etc., code; not just the SSL code.  The SSL documentation
 * included with this distribution is covered by the same copyright terms
 * except that the holder is Tim Hudson (tjh@mincom.oz.au).
 * 
 * Copyright remains Eric Young's, and as such any Copyright notices in
 * the code are not to be removed.
 * If this package is used in a product, Eric Young should be given attribution
 * as the author of the parts of the library used.
 * This can be in the form of a textual message at program startup or
 * in documentation (online or textual) provided with the package.
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *    "This product includes cryptographic software written by
 *     Eric Young (eay@mincom.oz.au)"
 *    The word 'cryptographic' can be left out if the rouines from the library
 *    being used are not cryptographic related :-).
 * 4. If you include any Windows specific code (or a derivative thereof) from 
 *    the apps directory (application code) you must include an acknowledgement:
 *    "This product includes software written by Tim Hudson (tjh@mincom.oz.au)"
 * 
 * THIS SOFTWARE IS PROVIDED BY ERIC YOUNG ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 * 
 * The licence and distribution terms for any publically available version or
 * derivative of this code cannot be changed.  i.e. this code cannot simply be
 * copied and put under another distribution licence
 * [including the GNU Public Licence.]
 */

#include <stdio.h>
#include <stdlib.h>
#ifndef MSDOS
#include <unistd.h>
#else
#include <io.h>
#define RAND
#endif

#include <time.h>
#include "des_ver.h"
#include "des_locl.h"

#ifdef VMS
#include <types.h>
#include <stat.h>
#else
#ifndef _IRIX
#include <sys/types.h>
#endif
#include <sys/stat.h>
#endif
#if defined(NOCONST)
#define const
#endif
#include "des.h"

#if defined(__STDC__) || defined(VMS) || defined(M_XENIX) || defined(MSDOS)
#include <string.h>
#endif

#ifdef RAND
#define random rand
#define srandom(s) srand(s)
#endif

#include <R.h>
#include <Rinternals.h>
#include "rdes.h"

#ifndef NOPROTO
extern void doencryption(void);
extern int uufwrite(unsigned char *data, int size, unsigned int num, FILE *fp);
extern void uufwriteEnd(FILE *fp);
extern int uufread(unsigned char *out,int size,unsigned int num,FILE *fp);
extern int uuencode(unsigned char *in,int num,unsigned char *out);
extern int uudecode(unsigned char *in,int num,unsigned char *out);
#else
extern void doencryption();
extern int uufwrite();
extern void uufwriteEnd();
extern int uufread();
extern int uuencode();
extern int uudecode();
#endif

#ifdef VMS
#define EXIT(a) return(a&0x10000000)
#else
#define EXIT(a) return(a)
#endif

SEXP rdesEncrypt( char **pkey, char **data )
{
	SEXP r_encrypted;
	
	unsigned char *rbyte = NULL;
	unsigned char *l_encrypted = NULL;
	int l_encrypted_len = 0;

        int i, r, P=0;

	if ( !pkey || !*pkey ) {
		fprintf( stderr, "key required\n" );
		return NULL;
	}
	if ( !data || !*data ) {
		fprintf( stderr, "data required\n" );
		return NULL;
	}

	/* simple DES encryption with binary output */
	cflag=0;
	do_encrypt=DES_ENCRYPT;
	dflag=0;
	strncpy(key,*pkey,KEYSIZB);
	hflag=0;
	bflag=0;
	uflag=0;
	flag3=0;

        data = PROTECT( coerceVector( data, RAWSXP )); P++;
	r = LENGTH( data );

	printf( "[%i,%i]\n", r, strlen( *data ) );

#if 0
	if ( doencryption_inmemory( buf_in, buf_in_len, r_encrypted->xxx, &l_encryped_len ) ) {
		return NULL;
	}
        for(i=length(x), r=0; i>0; i--, r++) {
           REAL(res)[r] = REAL(x)[i-1];
        }
#endif
        UNPROTECT(P);

	return r_encrypted;
}

SEXP rdesDecrypt( char **pkey, SEXP r_encrypted )
{
	SEXP r_data;
	
	unsigned char *l_data = NULL;
	int l_data_len = 0;

        int i, r, P=0;

	if ( !pkey || !*pkey ) {
		fprintf( stderr, "key required\n" );
		return NULL;
	}

	/* simple DES DEcryption with binary input */
	cflag=0;
	do_encrypt=DES_DECRYPT;
	dflag=0;
	strncpy(key,*pkey,KEYSIZB);
	hflag=0;
	bflag=0;
	uflag=0;
	flag3=0;

	l_data_len = length( r_encrypted );
        PROTECT( r_data = allocVector(RAWSXP, l_data_len )); P++;

#if 0
	if ( doencryption_inmemory( buf_in, buf_in_len, r_encrypted->xxx, &l_encryped_len ) ) {
		return NULL;
	}
        for(i=length(x), r=0; i>0; i--, r++) {
           REAL(res)[r] = REAL(x)[i-1];
        }
#endif
        UNPROTECT(P);

	return r_data;
}

int
callRDES( unsigned long *pflags, char  **pkey,
	char  **pinFile, char **poutFile,
	char **pcbcChecksumFile, char **puuencHeaderFile )
{
	unsigned long flags = 0;
	int i;
	struct stat ins,outs;
	char *p;
	char *in=NULL,*out=NULL;

	vflag=cflag=eflag=dflag=kflag=hflag=bflag=fflag=sflag=uflag=flag3=0;
	libdes_error=0;
	memset( key,0, KEYSIZB+1 );

	if ( !pflags ) {
		printf( "flags required\n" );
		return -1;
	}
	flags = *pflags;

	if ( !pkey || !*pkey ) {
		printf( "key required\n" );
		return -1;
	}
	strncpy(key,*pkey,KEYSIZB);

	if ( !pinFile || !*pinFile) {
		printf( "inFile required\n" );
		return -1;
	}
	in = *pinFile;

	if ( !poutFile || !*poutFile) {
		printf( "outFile required\n" );
		return -1;
	}
	out = *poutFile;
	
	if ( flags & RLIBDES_ENCRYPT ) {
		eflag=1;
	} else {
		dflag=1;
	}
	
	if ( flags & RLIBDES_3DES ) {
		flag3=1;
		longk=1;
	}

	if ( flags & RLIBDES_CBC_CHECKSUM ) {
		cflag=1;
		if ( !pcbcChecksumFile || !*pcbcChecksumFile ) {
			printf( "cbcChecksumFile required\n" );
			return -1;
		}
		strncpy(cksumname,*pcbcChecksumFile,200);
	}

	if ( flags & RLIBDES_SUNOS_COMPAT ) {
		;
	} else {
		longk=1;
	}

	if ( flags & RLIBDES_MODE_ECB ) {
		bflag=1;
	}

	if ( flags & RLIBDES_KEY_FMT_HEX ) {
		hflag = 1;
	}

	if ( flags & RLIBDES_UUENC_ENCRYPTED ) {
		uflag=1;
		if ( !puuencHeaderFile || !*puuencHeaderFile ) {
			printf( "uuencHeaderFile required\n" );
			return -1;
		}
		strncpy(uuname,*puuencHeaderFile,200);
	}
	/* We either
	 * do checksum or
	 * do encrypt or
	 * do decrypt or
	 * do decrypt then ckecksum or
	 * do checksum then encrypt
	 */
	if (((eflag+dflag) == 1) || cflag) {
		if (eflag) do_encrypt=DES_ENCRYPT;
		if (dflag) do_encrypt=DES_DECRYPT;
	} 

	if (	(in != NULL) &&
		(out != NULL) &&
#ifndef MSDOS
		(stat(in,&ins) != -1) &&
		(stat(out,&outs) != -1) &&
		(ins.st_dev == outs.st_dev) &&
		(ins.st_ino == outs.st_ino))
#else /* MSDOS */
		(strcmp(in,out) == 0))
#endif
			{
			fputs("input and output file are the same\n",stderr);
			EXIT(3);
			}

	if (!pkey)
		if (des_read_pw_string(key,KEYSIZB+1,"Enter key:",eflag?VERIFY:0))
			{
			fputs("password error\n",stderr);
			EXIT(2);
			}

	if (in == NULL)
		DES_IN=stdin;
	else if ((DES_IN=fopen(in,"r")) == NULL)
		{
		perror("opening input file");
		EXIT(4);
		}

	CKSUM_OUT=stdout;
	if (out == NULL)
		{
		DES_OUT=stdout;
		CKSUM_OUT=stderr;
		}
	else if ((DES_OUT=fopen(out,"w")) == NULL)
		{
		perror("opening output file");
		EXIT(5);
		}

#ifdef MSDOS
	/* This should set the file to binary mode. */
	{
#include <fcntl.h>
	if (!(uflag && dflag))
		setmode(fileno(DES_IN),O_BINARY);
	if (!(uflag && eflag))
		setmode(fileno(DES_OUT),O_BINARY);
	}
#endif

	doencryption();
	fclose(DES_IN);
	fclose(DES_OUT);
	EXIT(0);
}


#ifdef _LIBC
	extern int srandom();
	extern int random();
	extern unsigned long time();
#endif

int
doencryption_inmemory( unsigned char *buf_in, int buf_in_len, unsigned char *buf_out, int *buf_out_len )
{
	unsigned char *buf_in_pos = NULL;
	int buf_in_bytes_left = 0;

	unsigned char *buf_out_pos = NULL;
	int buf_out_bytes_left = 0;

	register int i;
	des_key_schedule ks,ks2;
	unsigned char iv[8],iv2[8];
	char *p;
	int num=0,j,k,l,rem,ll,len,last,ex=0;
	des_cblock kk,k2;
	FILE *O;
	int Exit=0;
	int free_buffers = 0;
#ifndef MSDOS
	static unsigned char buf[BUFSIZE+8],obuf[BUFSIZE+8];
#else
	static unsigned char *buf=NULL,*obuf=NULL;

	if (buf == NULL) {
		if (    (( buf=(unsigned char *)Malloc(BUFSIZE+8)) == NULL) ||
				((obuf=(unsigned char *)Malloc(BUFSIZE+8)) == NULL)) {
			fputs("Not enough memory\n",stderr);
			Exit=10;
			goto problems;
		}
		free_buffers ++;
	}
#endif

	if ( !buf_in || !buf_in_len || !buf_out || !buf_out_len ) {
		fprintf( stderr, "both input and output buffers required\n" );
		return -1;
	}
	buf_in_pos = buf_in;
	buf_out_pos = buf_out;
	buf_in_bytes_left = buf_in_len;
	buf_out_bytes_left = *buf_out_len;

	if (hflag) {
		j=(flag3?16:8);
		p=key;
		for (i=0; i<j; i++) {
			k=0;
			if ((*p <= '9') && (*p >= '0'))
				k=(*p-'0')<<4;
			else if ((*p <= 'f') && (*p >= 'a'))
				k=(*p-'a'+10)<<4;
			else if ((*p <= 'F') && (*p >= 'A'))
				k=(*p-'A'+10)<<4;
			else {
				fputs("Bad hex key\n",stderr);
				Exit=9;
				goto problems;
			}
			p++;
			if ((*p <= '9') && (*p >= '0'))
				k|=(*p-'0');
			else if ((*p <= 'f') && (*p >= 'a'))
				k|=(*p-'a'+10);
			else if ((*p <= 'F') && (*p >= 'A'))
				k|=(*p-'A'+10);
			else {
				fputs("Bad hex key\n",stderr);
				Exit=9;
				goto problems;
			}
			p++;
			if (i < 8)
				kk[i]=k;
			else
				k2[i-8]=k;
		}
		des_set_key((C_Block *)k2,ks2);
		memset(k2,0,sizeof(k2));

	} else if (longk || flag3) {
		if (flag3) {
			des_string_to_2keys(key,(C_Block *)kk,(C_Block *)k2);
			des_set_key((C_Block *)k2,ks2);
			memset(k2,0,sizeof(k2));
		} else {
			des_string_to_key(key,(C_Block *)kk);
		}
	} else {
		for (i=0; i<KEYSIZ; i++) {
			l=0;
			k=key[i];
			for (j=0; j<8; j++) {
				if (k&1) l++;
				k>>=1;
			}
			if (l & 1)
				kk[i]=key[i]&0x7f;
			else
				kk[i]=key[i]|0x80;
		}
	}

	des_set_key((C_Block *)kk,ks);
	memset(key,0, KEYSIZB + 1);
	memset(kk,0,KEYSIZB + 1);
	/* woops - A bug that does not showup under unix :-( */
	memset(iv,0,sizeof(iv));
	memset(iv2,0,sizeof(iv2));

	l=1;
	rem=0;
	/* encrypt */
	if (eflag || (!dflag && cflag)) {
		for (;buf_in_bytes_left;) {
			num = l = (BUFSIZE - rem) < buf_in_bytes_left ?
					(BUFSIZE - rem) : buf_in_bytes_left;

			memcpy( &(buf[rem]), buf_in_pos, num ); //num=l=fread(&(buf[rem]),1,BUFSIZE,DES_IN);
			buf_in_bytes_left -= num;
			buf_in_pos += num;

			l+=rem;
			num+=rem;

			rem=l%8;
			len=l-rem;
			if ( !buf_in_bytes_left ) {
				srandom((unsigned int)time(NULL));
				for (i=7-rem; i>0; i--)
					buf[l++]=random()&0xff;
				buf[l++]=rem;
				ex=1;
				len+=rem;
			} else {
				l-=rem;
			}

			if (bflag && !flag3)
				for (i=0; i<l; i+=8)
					des_ecb_encrypt(
						(des_cblock *)&(buf[i]),
						(des_cblock *)&(obuf[i]),
						ks,do_encrypt);
			else if (flag3 && bflag)
				for (i=0; i<l; i+=8)
					des_ecb2_encrypt(
						(des_cblock *)&(buf[i]),
						(des_cblock *)&(obuf[i]),
						ks,ks2,do_encrypt);
			else if (flag3 && !bflag)
				{
				char tmpbuf[8];

				if (rem) memcpy(tmpbuf,&(buf[l]),
					(unsigned int)rem);
				des_3cbc_encrypt(
					(des_cblock *)buf,(des_cblock *)obuf,
					(long)l,ks,ks2,(des_cblock *)iv,
					(des_cblock *)iv2,do_encrypt);
				if (rem) memcpy(&(buf[l]),tmpbuf,
					(unsigned int)rem);
				}
			else
				{
				des_cbc_encrypt(
					(des_cblock *)buf,(des_cblock *)obuf,
					(long)l,ks,(des_cblock *)iv,do_encrypt);
				if (l >= 8) memcpy(iv,&(obuf[l-8]),8);
				}
			if (rem) memcpy(buf,&(buf[l]),(unsigned int)rem);

			i=0;
			if ( l <= buf_out_bytes_left ) { // fwrite 
				memcpy( buf_out_pos, obuf, l );
				buf_out_pos += l;
				buf_out_bytes_left -= l;
			} else {
				fprintf( stderr, "output buffer too small\n" );
				Exit = 8;
				goto problems;
			}
		}
		*buf_out_len = buf_out_pos - buf_out;
	} else /* decrypt */ {
		ex=1;
		for (;buf_in_bytes_left;) {
			/* first "read" */
			if (ex) {

				l = BUFSIZE < buf_in_bytes_left ?  BUFSIZE : buf_in_bytes_left; 

				memcpy( buf, buf_in_pos, l ); // l=fread(buf,1,BUFSIZE,DES_IN);
				buf_in_bytes_left -= l;
				buf_in_pos += l;

				ex=0;
                                if (l > 0) {
					rem=l%8;
					l-=rem;
				}
			}

			if (bflag && !flag3)
				for (i=0; i<l; i+=8)
					des_ecb_encrypt(
						(des_cblock *)&(buf[i]),
						(des_cblock *)&(obuf[i]),
						ks,do_encrypt);
			else if (flag3 && bflag)
				for (i=0; i<l; i+=8)
					des_ecb2_encrypt(
						(des_cblock *)&(buf[i]),
						(des_cblock *)&(obuf[i]),
						ks,ks2,do_encrypt);
			else if (flag3 && !bflag)
				{
				des_3cbc_encrypt(
					(des_cblock *)buf,(des_cblock *)obuf,
					(long)l,ks,ks2,(des_cblock *)iv,
					(des_cblock *)iv2,do_encrypt);
				}
			else
				{
				des_cbc_encrypt(
					(des_cblock *)buf,(des_cblock *)obuf,
				 	(long)l,ks,(des_cblock *)iv,do_encrypt);
				if (l >= 8) memcpy(iv,&(buf[l-8]),8);
				}

			/* next "read" */
			ll = BUFSIZE - rem < buf_in_bytes_left ?  BUFSIZE - rem : buf_in_bytes_left; 
			memcpy( &buf[rem], buf_in_pos, ll ); // ll=fread(&(buf[rem]),1,BUFSIZE,DES_IN);
			buf_in_bytes_left -= ll;
			buf_in_pos += ll;

			ll+=rem;
			rem=ll%8;
			ll-=rem;

			if ( ll == 0 ) {
				last=obuf[l-1];

				if ((last > 7) || (last < 0)) {
					fputs("The file was not decrypted correctly.\n", stderr);
					last=0;
				}
				l=l-8+last;
			}
			i=0;

			if ( l <= buf_out_bytes_left ) { // fwrite 
				memcpy( buf_out_pos, obuf, l );
				buf_out_pos += l;
				buf_out_bytes_left -= l;
			} else {
				fprintf( stderr, "output buffer too small\n" );
				Exit = 8;
				goto problems;
			}
			l=ll;
			if ( l == 0 ) break;
		}
	}

problems:
	memset(buf,0,sizeof(buf));
	memset(obuf,0,sizeof(obuf));
	memset(ks,0,sizeof(ks));
	memset(ks2,0,sizeof(ks2));
	memset(iv,0,sizeof(iv));
	memset(iv2,0,sizeof(iv2));
	memset(kk,0,sizeof(kk));
	memset(k2,0,sizeof(k2));
	memset(b,0,sizeof(b));
	memset(bb,0,sizeof(bb));
	memset(cksum,0,sizeof(cksum));
#ifdef MSDOS
	if ( free_buffers ) {
		free( buf );
		free( obuf );
	}
#endif
	return Exit;
}
