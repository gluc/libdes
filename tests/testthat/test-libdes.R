# Run this like so:
#
# 1. build libdes.bbg package
# Then type into the RStudio console:

# install.packages("devtools")
# library(devtools)
# devtools::test()



context("des")

test_that("roundtrip", {
  
  #create a temporary file
  fileIn <- tempfile()
  #Write something into it
  fileContent <- "Hello baby"
  cat(fileContent, file = fileIn)
  
  
  #name of the target encrypted file
  fileEnc <- paste0(fileIn, ".enc")
  
  key <- "Ab4qY9qm"
  
  #call the new method "callRDES" in the libdes.dll
  
  result <- .C( "callRDES", as.integer( 1 ), key, fileIn, fileEnc, "", "" )
  
  # now decrypt
  
  fileDec <- paste0(fileIn, ".dec")
  
  result <- .C("callRDES", 
     as.integer( 0 ),
     key,
     fileEnc,
     fileDec, "", "")
  
  
  #read in decrypted file
  helloBaby <- readChar(fileDec, file.info(fileDec)$size)
  
  #check that content is the same
  expect_equal(fileContent, helloBaby)
})
