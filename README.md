# Flash dump analyzer

Load and dump information from flash dumps and shadowboot ROMs

Detect type of file as well as partial files (ie. extracted bootloader)


# Usage:
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

# Requirements:
* libssl
* pycrypto
* hashlib
