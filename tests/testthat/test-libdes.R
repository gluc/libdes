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
  
  argv = c("-E", "-u", "-k", "Ab4qY9qm", fileIn, fileEnc)
  
  #call the new method "calldes" in the libdes.bbg.dll
  res <- .C("calldes", 
            argv = argv, 
            PACKAGE = "libdes.bbg")
  
  
  # now decrypt
  
  fileDec <- paste0(fileIn, ".dec")
  argv = c("-D", "-u", "-k", "Ab4qY9qm", fileEnc, fileDec)
  res <- .C("calldes", 
            argv = argv, 
            PACKAGE = "datalicenseR")
  
  #read in decrypted file
  helloBaby <- readChar(fileDec, file.info(fileDec)$size)
  
  #check that content is the same
  expect_equal(fileContent, helloBaby)
})
