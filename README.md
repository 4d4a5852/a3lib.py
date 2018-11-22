# a3lib.py #

python3 tool library for Arma 3

## Features ##

* python classes for working with PBOs, keys and signatures
* basic command line tools for:
    * PBO creation, listing and unpacking
    * conversion of RSA keys (DER or PEM format) to .biprivatekey/.bikey format
    * signature (.bisign) creation and verification


## Usage ##
### Help ###

```
$ a3lib.py --help
usage: a3lib.py [-h] [-v | -q] {key,sign,verify,bisign,pbo} ...

Work with BI PBOs, signatures and keys.

positional arguments:
  {key,sign,verify,bisign,pbo}
                        sub-command help
    key                 print/convert keys
    sign                sign a PBO
    verify              verify the signature of a PBO
    bisign              print bisign/extract public key
    pbo                 create/extract/list PBO files

optional arguments:
  -h, --help            show this help message and exit
  -v, --verbose         increase output verbosity
  -q, --quiet
```
```
$ a3lib.py key --help
usage: a3lib.py key [-h] [--privout] [--pubin] [--pubout]
                    [--keyform {bi,der,pem}]
                    key

positional arguments:
  key                   public/private key

optional arguments:
  -h, --help            show this help message and exit
  --privout             write .biprivatekey
  --pubin               public key as input
  --pubout              write .bikey
  --keyform {bi,der,pem}
                        format of the input key - default: bi
```
```
$ a3lib.py sign --help
usage: a3lib.py sign [-h] [--keyform {bi,der,pem}] [--version {2,3}] key pbo

positional arguments:
  key                   private key
  pbo                   pbo to be signed

optional arguments:
  -h, --help            show this help message and exit
  --keyform {bi,der,pem}
                        format of the key - default: bi
  --version {2,3}       signature version - default: 3
```
```
$ a3lib.py bisign --help
usage: a3lib.py bisign [-h] [--pubout] sig

positional arguments:
  sig         bisign file

optional arguments:
  -h, --help  show this help message and exit
  --pubout    extract public key from signature
```
```
$ a3lib.py verify --help
usage: a3lib.py verify [-h] [--keyform {bi,der,pem}] [--privin] key pbo sig

positional arguments:
  key                   public key
  pbo                   pbo to be verified
  sig                   signature to be verified

optional arguments:
  -h, --help            show this help message and exit
  --keyform {bi,der,pem}
                        Format of the key - default: bi
  --privin              private key as input
```
```
$ a3lib.py pbo --help
usage: a3lib.py pbo [-h] (-c | -i | -l | -x) -f PBO [--include INCLUDE]
                    [--exclude EXCLUDE] [-e NAME VALUE] [--no-pboprefixfile]
                    [--no-recursion] [--timestamps]
                    [FILE [FILE ...]]

positional arguments:
  FILE                  files to be added

optional arguments:
  -h, --help            show this help message and exit
  -c, --create          create a new pbo file
  -i, --info            print information about the pbo file
  -l, --list            list the content of the pbo file
  -x, --extract         extract a pbo file
  -f PBO, --file PBO    pbo file
  --include INCLUDE     include filter pattern
  --exclude EXCLUDE     exclude filter pattern
  -e NAME VALUE, --header_extension NAME VALUE
                        header extension to be added
  --no-pboprefixfile    don't use a $PBOPREFIX$ file
  --no-recursion        don't automatically ascend into directories when
                        adding files
  --timestamps          update timestamps when extracting PBOs
```

### Examples ###

* list PBO content:  
    `a3lib.py pbo -lf test.pbo`

* unpack PBO into current directory:  
    `a3lib.py pbo -xf test.pbo`

* unpack PBO into current directory - only *.cpp files:  
    `a3lib.py pbo -xf test.pbo --include *.cpp`

* unpack PBO into current directory - exclude *.cpp files:  
    `a3lib.py pbo -xf test.pbo --exclude *.cpp`

* create PBO and add config.cpp and folder abc:  
    `a3lib.py pbo -cf test.pbo config.cpp abc`

* create new private key and convert to bi format:  
    `openssl genpkey -algorithm rsa -outform der -out mytestkey.der`  
    `a3lib.py key --keyform der mytestkey.der --privout --pubout`

* sign PBO:  
    `a3lib.py sign mytestkey.biprivatekey test.pbo`

* sign PBO with key in DER format:  
    `a3lib.py sign --keyform der mytestkey.der test.pbo`

* verify signature:  
    `a3lib.py verify mytestkey.bikey test.pbo test.pbo.mytestkey.bisign`

### Class Documentation ###

```python
import a3lib
help(a3lib)
```

## Known issues/limitations ##

* management of file handles is quite a mess
* only basic PBO support:
    * no compression
    * (currently) no support for mission type PBOs
    * no backwards compatibility
* almost no exception handling: garbage in -> garbage out
* no tests
