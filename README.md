# Erebus
Erebus is a payload generator written in Nim. It has many AV/EDR evasion features such as ETW patching, NTDLL unhooking via the Perun's Fart technique, custom GetProcAddress implementation, sandbox checking, and shellcode encoding/encryption with UUID, RC4, and AES. 

# Installation
Being built with Nim means, obviously, Nim must be installed. Specifically, 1.6.10, which at the time of writing is the latest (stable) version. As there are some semi hardcoded values, install Nim using ChooseNim. MinGW and GCC are also required.

Other dependencies are OpenSSL (must be in /usr/bin. Installed by default in most cases but can be installed with the system package manager), xxd (must be in /usr/bin. Installed by default in most cases but can be installed with the system package manager) and some Nim modules. 

These are: argparse, winim, ptr_math, and nimcrypto. Each can be installed with Nim's package manager Nimble, i.e `nimble install <modudle>`. You can also try running `nim dependencies` to install these modules after cloning the repo (and cd into it), but YMMV as this feature has not been tested.

Once all dependencies are installed, running `nim build` should compile the project for you. 
