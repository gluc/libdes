TestDES <- function(SUNOS = FALSE, HEX_KEY = FALSE, ECB = FALSE, UUENC = FALSE, uuencFile = "") {
  
  #create a temporary file
  fileIn <- tempfile()
  #Write something into it
  fileContent <- "Hello baby"
  cat(fileContent, file = fileIn)
  
  
  #name of the target encrypted file
  fileEnc <- paste0(fileIn, ".enc")
  
  key <- "Ab4qY9qm"
  
  #call the new method "callRDES" in the libdes.dll
  
  result <- EncryptFile(sourceFile = fileIn,
                        encryptedFile =  fileEnc,
                        key, 
                        SUNOS = SUNOS, 
                        HEX_KEY = HEX_KEY, 
                        ECB = ECB, 
                        UUENC = UUENC,
                        uuencFile = uuencFile)
  
  # now decrypt
  
  fileDec <- paste0(fileIn, ".dec")
  
  
  result <- DecryptFile(fileEnc, fileDec, key, SUNOS, HEX_KEY, ECB, UUENC)
  
  #read in decrypted file
  helloBaby <- readChar(fileDec, file.info(fileDec)$size)
  
  #check that content is the same
  expect_equal(fileContent, helloBaby)
  
}