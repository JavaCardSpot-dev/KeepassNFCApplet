# KeepassNFC [![Build Status](https://travis-ci.org/JavaCardSpot-dev/KeepassNFCApplet.svg?branch=master)](https://travis-ci.org/JavaCardSpot-dev/KeepassNFCApplet) [![Coverage Status](https://coveralls.io/repos/github/JavaCardSpot-dev/KeepassNFCApplet/badge.svg?branch=master)](https://coveralls.io/github/JavaCardSpot-dev/KeepassNFCApplet?branch=master)
## IMPORTANT
**This repository is used for class [PV204 Security Technologies at Masaryk University](https://is.muni.cz/auth/predmety/predmet?lang=en;setlang=en;pvysl=3141746). All meaningful improvements will be attempted to be pushed to upstream repository in June 2018.**

## Overview
[KeePass Password Safe](https://keepass.info/) is an open source password manager that aims to store passwords securely.

KeepassNFC is an applet that can protect the secret key of the KeePass database.

This applet was based on the project [smartcard_crypto_applet](https://github.com/nfd/smartcard_crypto_applet) and can be run on javacard platform with [JCRE](http://javacardos.com/wiki/index.php/home/index/index/model/jcre/app_name/JCRESpec01intro.html?ws=github&prj=KeepassNFC) version 2.2.x or above.
It is meant to be used in a card supporting NFC (Near Field Communication) technology.

## Compiling the project
This project has two different build systems that can be used. [JCIDE](#jcide) is the one originally used, while the Gradle integration has been added later using the [template](https://github.com/crocs-muni/javacard-gradle-template-edu) from [@crocs-muni](https://github.com/crocs-muni/).

### [JCIDE](http://www.javacardos.com/tools/index.html?ws=github&prj=KeepassNFC#JCIDE)
A project file (KeepassNFC.jcproj) has been created for the users of [JCIDE](http://www.javacardos.com/tools/index.html?ws=github&prj=KeepassNFC#JCIDE). If you have already installed the [JCIDE](http://www.javacardos.com/tools/index.html?ws=github&prj=KeepassNFC#JCIDE), only a simple double-clicking on this file is needed to start the development environment.
You can view, edit, build or debug the code with [JCIDE](http://www.javacardos.com/tools/index.html?ws=github&prj=KeepassNFC#JCIDE), a powerful Javacard Integrated Development Environment.
You can use [pyApdutool](http://javacardos.com/tools/index.html?ws=github&prj=KeepassNFC#pyApduTool) to download and install the applet, please reference the [topic](http://javacardos.com/javacardforum/viewtopic.php?f=3&t=38&ws=github&prj=KeepassNFC) in the [JavaCardOS](http://javacardos.com/javacardforum/?ws=github&prj=KeepassNFC) for the operation detail.

Support for this configuration is guaranteed until commit [701cdfc](https://github.com/JavaCardSpot-dev/KeepassNFCApplet/commit/701cdfc89de7831d23bb91bf415e1e20b1ee72c4).

### Gradle
This configuration gives the ability to easily compile and convert the applet to cap files, it has support for easy tests creation, including test coverage.
Also, it provides integration with [Travis CI](https://travis-ci.org/) platform (and easily with any other CI platform).
It additionally provides the means to execute on both real cards and [JCardSim.org](https://jcardsim.org/) simulator.

This build configuration can be used with all the IDEs that provide integration (native or by plugins) with Gradle (IntelliJ, NetBeans, Eclipse...).

After recursively cloning the repository (to gather all the JavaCard SKDs),
```bash
git clone --recurse-submodules git@github.com:JavaCardSpot-dev/KeepassNFCApplet.git 
```
you can choose the desired JavaCard SDK to use by setting the `JCSDK` environment variable (by default it is empty, and the minimum required SDK version will be used). Then simply run
```bash
./gradlew buildJavaCard --info
JCSDK=jc304 ./gradlew buildJavaCard --info
```
to get the `.cap` file. It will be located under `bin/net/lardcave/keepassnfcapplet/{JCSDK}/keepassnfcapplet.cap`

## Usage
Here, the _user_ is intended as both you and the _client application_.

Also, when talking about APDU headers, the length will be always omitted, just like P1 and P2, except when needed.

### General functionality
Actually, the applet is able to decrypt the user-supplied database using AES-256. Future development will include also its encryption, and possibly support for more algorithms (Twofish/ChaCha20).

The applet uses three classes of commands:
 * `0x90`: includes commands always accessible by any user
 * `0xA0`: includes all PIN-related commands. Some of them are freely accessible (PIN verifications), others require the Master PIN to have been previously verified.
 * `0xB0`: any command under this class needs the User PIN to have been previously verified. This class includes all actual implementation of the required functionality to decrypt the database.

### PIN management
Authentication is provided by the means of two PIN verifications. Both PINs initial values are actually hardcoded. 
 * **Master PIN**: this PIN is required to change both itself and the User PIN. Its default (hardcoded) value is the string `123456`. For increased security its minimum length is 6.
 * **User PIN**: this PIN is needed by the actual decryption functionality. Its default (hardcoded) value is the string `1234`, with a minimum required length of 4 characters.

Both PINs are recommended to be changed by the final user using commands under the `0xA0` class.

Both PIN verifications are kept valid until the card is extracted (or the applet is deselected).

### Applet configuration
For applet configuration, all commands are of class `0xB0`, and as such require verify User PIN (**A082**) to have been called successfully.
 1. As first one-time-only step, the user will let the card generate an internal key pair (2048b RSA)(**B075**).
 1. After generation, the user will be able to get the public key by means of exponent and modulus (**B070**).
 1. Then, the user will send its Password Key to the applet, encrypted with the card's public key (**B076**, **B071**).

After calling these commands, the applet is configured to actually decrypt the KeePass database.

### Applet usage
For applet usage, all commands are of class `0xB0`, and as such require verify User PIN (**A082**) to have been called successfully. Also, the configuration is considered to be done.

Each usage is identified by a _transaction_, with related transaction key (AES-128).
The user is required to:
 1. generate a AES-128 transaction key, encrypt it with card's public key and send it to card using write to scratch (**B076**).
 1. send to card IVs to initialize password and transaction ciphers (**B072**).
 1. send to card the password-encrypted database split in blocks, getting the same transaction-encrypted (**B073**).
 1. decrypt each block with transaction key, obtaining plaintext database.

### Infomative commands
The user can obtain two different information pieces about the status of the applet, without changing its state and without any authentication:
 * version of the applet (**9074**, ~~**B074**~~)
 * number of PIN trials remaining (**9072**). This can explain why some actions may be blocked in different situations.

### APDU formats
| Header | Name | Payload (plaintext) | Functionality | Authenticated | Requirements | Response format |
|:--- |:--- |:--- |:--- |:--- |:--- |:--- |
| **9072** | lock reason/PIN trials | _empty_ | Return number of trials remaining for both PINs. In future can contain more information | | | `mmuu`, with `mm` remaining trials for Master PIN and `uu` for User PIN
| **9074**<br>~~**B074**~~* | get version | _empty_ | Return applet version | | | `01vv`, with `vv` the actual version.
| **A080** | verify Master PIN | Master PIN | Verify given Master PIN against the stored one | | | <ul><li>if successful `01` <li>if wrong PIN `SW=0x99nn`, with `nn` as number of trials remaining </ul> |
| **A081** | set Master PIN | New Master PIN | Set Master PIN to given data | Master (**A080**) | | | 
| **A082** | verify User PIN | User PIN | Verify given User PIN against the stored one | | | <ul><li>if successful `01` <li>if wrong PIN `SW=0x99nn`, with `nn` as number of trials remaining </ul> |
| **A083** | set User PIN | New User PIN | Set User PIN to given data | Master (**A080**) | | |
| **B070** | get public key | `010000` | Get public key's exponent | User (**A082**) | **B075** successfully called | `01ssssk...`, with `ssss` a short for exponent length, and `k...` the actual exponent
| **B070** | get public key | `02oooo` | Get public key's modulus from offset `oooo` | User (**A082**) | **B075** successfully called | `01ssssSSSSk...`, with `ssss` a short for the bytes sent, `SSSS` a short for the missing bytes after the sent ones, and `k...` the actual modulus part
| **B070** | get public key | `xxoooo` | --- | User (**A082**) | | `02` (failure) when `xx` different from `01` or `02`
| **B071** | set password key | _empty_ | Decrypt first bytes in scratch area as password key (AES-256, saved also after disconnection) | User (**A082**) | **B075** successfully called and **B076** used to store encrypted password key in scratch area | `01` if successful
| **B072** | prepare decryption | password & transaction IVs (16+16 bytes) | Decrypt first bytes in scratch area as transaction key (AES-128, saved only for the session). Initialize password cipher for decryption and transaction cipher for encryption. | User (**A082**) | **B076** used to store encrypted transaction key in scratch area | `01` if successful
| **B073**<br>`P1=80` | decrypt block | encrypted block | Decrypts given data with password cipher expecting more data. Then encrypts the result with transaction cipher. | User (**A082**) | **B072** successfully called | `01b...`, with `b...` actual block
| **B073**<br>`P1!=80` | decrypt block | encrypted block | Same as above, but as last block. This will also reset ciphers. | User (**A082**) | **B072** successfully called | `01b...`, with `b...` actual block
| **B075** | generate key pair | _empty_ | Generate card's key pair. | User (**A082**) | | `01ssss`, with `ssss` a short for key length.
| **B076** | write to scratch | `oodd...` | Store data (`dd...`) in internal scratch area at offset `oo` | User (**A082**) | | `01ssss`, with `ssss` a short for free space after saved data.

**B074** instruction to get version is maintained only for compatibility reasons, and it's deprecated. Nevertheless, since it's a `B0`-class instruction, it still needs correct User PIN verification.

### Error codes
Apart from standard exception codes, the following specific SW codes are used:

| SW | Meaning | `ISO7816` equivalence |
|:--- |:--- |:--- |
| **97nn** | Action requires Master PIN verification, but **A080** wasn't successfully called. `nn` contains remaining numebr of trials. | |
| **98nn** | Action requires User PIN verification, but **A082** wasn't successfully called. `nn` contains remaining number of trials. | |
| **99nn** | The verification of Master/User PIN gone wrong. `nn` contains remaining number of trials. | |
| **6700** | Input data has wrong length compared to expected one. | `SW_WRONG_LENGTH` |
| **6A80** | Input data has different values than expected. | `SW_WRONG_DATA` |
| **6982** | In case of error caused by supposed tampering. | `SW_SECURITY_STATUS_NOT_SATISFIED` |
| **F1tt** | A crypto-related exception occurred. `tt` from `01` to `05` are standard CryptoException reasons, while `09` is used for rare situation when evaluating a number too big. This only happened if skipping some commands while setting password/trasaction keys. | |

## Future work
Help is always appreciated! Please read these suggestions for what to do, and always follow the [contibution rules](CONTRIBUTING.md)!

This applet can be improved in several ways:

 - [ ] Drop usage of `01`/`02` to show success/failure of commands, and just use `SW` codes
 - [ ] Offer method to know the maximum amount of data that can be sent each time
 - [ ] Support for long APDUs
 - [ ] Support for encryption of database
 - [ ] Support for ChaCha20/Twofish/other algorithms supported by KeePass or its plugins
 - [ ] HMAC encrypted communication
 - [ ] Manage states of the applet to prevent wrong commands to be called
 - [ ] Setting initial Master/User PINs during installation with a payload
 - [ ] DH-like key derivation instead of PIN/transaction key (with shared secret set during installation)
 - [ ] Optimize for execution on real cards (currently, it can take [several seconds or minutes](#timings) to perform specific actions)

Also the repository can be improved:

 - [ ] Leave a single build system, or correctly maintain/link both
 - [ ] Provide multiple client implementations (different simulators/libraries)
 - [ ] Run tests using different simulators _and_ directly calling methods
 - [ ] Add tests to cover all the applet code. Also, test and check coverage of clients.

## Known compatibilities
Until [701cdfc](https://github.com/JavaCardSpot-dev/KeepassNFCApplet/commit/701cdfc89de7831d23bb91bf415e1e20b1ee72c4) it should work on [JC30M48](http://www.javacardos.com/store/javacard-jc30m48cr.php?ws=github&prj=KeepassNFC), the downloading and installation have been tested on this card.

Until June 2018 it was successfully tested with [NXP J2E 081 (NXP JCOP v2.4.x)](https://smartcard-atr.appspot.com/parse?ATR=3BF91300008131FE454A434F503234325233A2).

## Timings
Some profiling has been performed for all the commands (timings are in _ms_, average over 20 trials, smartcard [NXP J2E 081](#known-compatibilities)):

| Header | Avg timing | Timing range | Notes |
|:--- | ---:|:---:|:--- |
| **9072** | 7 | 7 - 8 | (get lock reason/remaining PINs), direct read |
| **9074** | 7 | 7 - 9 | (get version), direct read |
| **A080** | 37 | 37 - 39 | (verify Master PIN) |
| **A081** | 33 | 33 - 34 | (set Master PIN) |
| **A082** | 37 | 37 - 38 | (verify User PIN) |
| **A083** | 33 | 32 - 34 | (set User PIN) |
| **B070**<br>`010000` | 13 | 13 - 14 | (get Card Key exponent) Supposed one execution every usage. |
| **B070**<br>`020000` | 44 | 44 - 45 | (get Card Key modulus - first part) Supposed one execution every usage. |
| **B071** | 714 | 714 - 716 | (set password key) Supposed one execution every long time. |
| **B072** | 699 | 698 - 700 | (set transaction key) Supposed one execution every usage. |
| **B073**<br>`P1!=80` | 96 | 95 - 97 | (decrypt one block) Decrypting 128 bytes unique block. |
| **B075** | 21660 | 5557 - 54592 | (generate card key) Supposed one execution every long time. |
| **B076** | 14 | 14 - 15 | (write to scratch) Writing 16 bytes to scratch ~encrypted transaction key. |
| **B076** | 18 | 18 | (write to scratch) Writing 32 bytes to scratch ~encrypted password key. |
| **B076** | 26 | 26 - 27 | (write to scratch) Writing 64 bytes to scratch, more than needed by keys. |

About the **B073** command (block decryption): a fully populated KeePass database can be long around 200 KiB, that corresponds to 1600 executions of given command.
These result in a total execution time of around 150 seconds, or 2.5 minutes. This _should_ be improved.

## Maintainers
The original creator of the project is the [JavaCardOS](http://www.javacardos.com/) community.

As the initial [notice](#important) explains, this project will be maintained by students of the Masaryk University about until June 2018.
