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
check the help pages:

* `a3lib.py --help`
* `a3lib.py key --help`
* `a3lib.py sign --help`
* `a3lib.py verify --help`
* `a3lib.py pbo --help`

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

* sign PBO:  
    `a3lib.py sign test.pbo xyz.biprivatekey`

* verify signature:  
    `a3lib.py verify xyz.bikey test.pbo test.pbo.xyz.bisign`

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