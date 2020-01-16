# Flash dump analyzer overview

Load and dump information from flash dumps and shadowboot ROMs

Detect type of file as well as partial files (ie. extracted bootloader)


## flash-dump Usage:
    ./flash-dump.py image.bin -c cpukey -x section

    -x  Extract section(s)

        Valid sections are:
            nandheader, keyvault, smc, smcconfig, sb, cb, sc, sd, cd, se, ce, cf, cg, cf1, cg1, kernel, hv

        Use 'all' to extract all sections

        ex. python3 flash-dump.py image.bin -x sb
        ex. python3 flash-dump.py image.bin -x sb sd smc
        ex. python3 flash-dump.py image.bin -x all


    -e  Enumerate section(s)

        Enumerate information about the given sections (if available)

        Valid sections are as above

        ex. python3 flash-dump.py image.bin -e se
        ex. python3 flash-dump.py image.bin -e nandheader sb kv
        ex. python3 flash-dump.py image.bin -e all


    -r  Replace section
        Provided replacement must be decrypted (plaintext) as well as decompressed in the case of kernel and hv

        Valid sections are as above

        ex. python3 flash-dump.py image.bin -r se se_patched_plain.bin
        ex. python3 flash-dump.py image.bin -r kernel xboxkrnl_patched_plain_dec.bin


    -d  Decrypt section(s)

        Attempts to decrypt the given sections in place or treat input as decrypted

        Valid sections are as above

        Used in combination with extract and replace

        ex. python3 flash-dump.py image.bin -d sb smc -x sb sd smc


    -c  CPU key
        Required to decrypt bootloaders CD and onward on retails with CB >= 1920
        Required to decrypt keyvault
        Required to replace encrypted sections

        By default the programs looks for a binary file, "cpukey" in the "data" directory

        ex. python3 flash-dump.py image.bin -c 48a3e35253c20bcc796d6ec1d5d3d811


     -k  Key file path

         By default the programs looks for a binary file, "keyfile" in the "data" directory

         This file should be the binary representation of the 1BL key

         ex. python3 flash-dump.py image.bin -x kernel -k /path/to/keys.txt

     -s  Sign
         Provided file must be decrypted (plaintext) SD

         Signs the given 4BL with the 4BL private key

         ex. python3 flash-dump.py -s SD_dec.bin


    --debug  Verbose output for debugging


    -v  Version
    
# XeCrypt RSA to PEM (XeRSA2PEM) Overview

Convert big endian, bignumber formatted XeCryptRSA objects (binary) to PEM files.
    
## xersa2pem Usage

    usage: XeRSA2PEM [-h] -t {public,private} [-s {1024,1536,2048,4096,guess}]
                     [-r] [-v] [-d]
                     xersaobj pempath
    
    Parse big-endian XeRSA* struct formatted binaries into PEM files
    
    positional arguments:
      xersaobj              Path to XeRSA* struct formatted binary file
      pempath               Path to PEM output file
    
    optional arguments:
      -h, --help            show this help message and exit
      -t {public,private}, --type {public,private}
                            Type of XeRSA object
      -s {1024,1536,2048,4096,guess}, --size {1024,1536,2048,4096,guess}
                            Size of XeRSA key
      -r, --reverse         Reverse process: PEM to binary file
      -v, --verbose         Set verbose-level output
      -d, --debug           Set debug-level output
    
    Example Usage:
    
    Convert 4096-bit private key (XeRsaPriv4096) binary file to pem:
    
      python3 xersa2pem.py -t private -s 4096 XeRsaPriv4096.bin XeRsaPriv4096.pem
    
    Convert unknown size private key binary file to pem:
    
      python3 xersa2pem.py -t private -s guess XeRsaPriv.bin XeRsaPriv.pem
    
    Convert unknown size private key binary file to pem:
    
      python3 xersa2pem.py -t private -s guess XeRsaPriv.bin XeRsaPriv.pem
    
    Convert key PEM file to appropriate binary:
    
      python3 xersa2pem.py -r XeRsaPriv.bin XeRsaPriv.pem

## xecrypt Library Usage

This will likely be moved to its own repository (and pip) in the future, but for the time being you can use the various
 libraries provided in this for your own tools by importing from the [lib](/lib) directory

# Dependencies / Environment:

I recommend using the virtualenv package to automatically install all dependencies in the [requirements.txt](/requirements.txt)

`virtualenv --python=python3 environment`

`source environment/bin/activate`

`pip install -r requirements.txt`
