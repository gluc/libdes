
#' Encrypt a file with the DES algorithm
#'
#' @export
EncryptFile <- function(sourceFile, encryptedFile, key, SUNOS = FALSE, HEX_KEY = FALSE, ECB = FALSE, UUENC = FALSE) {
  
  opts <- GetOptions(ENCRYPT = TRUE, 
                     SUNOS, 
                     HEX_KEY,
                     THREEDES = FALSE, 
                     ECB, 
                     UUENC)
    
  .C( "callRDES", opts, key, sourceFile, encryptedFile, "", "" )
}


GetOptions <- function(ENCRYPT = FALSE, SUNOS = FALSE, HEX_KEY = FALSE, THREEDES = FALSE, ECB = FALSE, UUENC = FALSE) {
  #define RLIBDES_ENCRYPT       0x00000001     // encrypt if set, else decrypt 
  #define RLIBDES_SUNOS_COMPAT 0x00000002 // enable/disable SUNOS compatibility 
  #define RLIBDES_CBC_CHECKSUM  0x00000004 // calculate cbc-checksum or not 
  #define RLIBDES_KEY_FMT_HEX    0x00000008 // if key string is in hex instead of b64 
  #define RLIBDES_3DES             0x00000010 // set to use 3DES 
  #define RLIBDES_MODE_ECB    0x00000020 // if set, then encryption mode is ECB, if not - CBC 
  #define RLIBDES_UUENC_ENCRYPTED 0x00000040 // set if encrypted data is\should be uuencoded (uuencHeaderFile must be set)
  opts <- 0
  if (ENCRYPT) opts <- opts + 1
  if (SUNOS) opts <- opts + 2
  if (HEX_KEY) opts <- opts + 8
  if (THREEDES) opts <- opts + 10
  if (ECB) opts <- opts + 20
  if (UUENC) opts <- opts + 40
  return (opts)
}