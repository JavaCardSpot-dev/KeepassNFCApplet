# KeepassNFC [![Build Status](https://travis-ci.org/JavaCardSpot-dev/KeepassNFCApplet.svg?branch=master)](https://travis-ci.org/JavaCardSpot-dev/KeepassNFCApplet)
## IMPORTANT
**This repository is used for class [PV204 Security Technologies at Masaryk University](https://is.muni.cz/auth/predmety/predmet?lang=en;setlang=en;pvysl=3141746). All meaningful improvements will be attempted to be pushed to upstream repository in June 2018.**

## Overview
KeePass is an open source password manager that aims to store passwords securely, enabling the user to keep all its sensitive password in KeePass encrypted database, which can be locked by a single Master Password (MP). Hence, the user is required to remember only that single password/key to unlock the database to retrieve his passwords and edit them
KeepassNFC is an applet in javacard platform that can protect the secret key of KeePass database. It was based on the project [smartcard_crypto_applet](https://github.com/nfd/smartcard_crypto_applet) and can be run on javacard platform with [JCRE](http://javacardos.com/wiki/index.php/home/index/index/model/jcre/app_name/JCRESpec01intro.html?ws=github&prj=KeepassNFC) version 2.2.x or above.
KeePass is a famous software about password managerment.

KeepassNFC applet is meant to use the card with NFC (near field communication) technology which enables the user with contactless use of the card installed with this applet.

## Compiling the project
This project has two different build systems that can be used. [JCIDE](#jcide) is the one originally used, the Gradle integration has been added later using the [template](https://github.com/crocs-muni/javacard-gradle-template-edu) from [@crocs-muni](https://github.com/crocs-muni/).

### [JCIDE](http://www.javacardos.com/tools/index.html?ws=github&prj=KeepassNFC#JCIDE)
A project file (KeepassNFC.jcproj) has been created for the users of [JCIDE](http://www.javacardos.com/tools/index.html?ws=github&prj=KeepassNFC#JCIDE). If you have already installed the [JCIDE](http://www.javacardos.com/tools/index.html?ws=github&prj=KeepassNFC#JCIDE), only a simple double-clicking on this file is needed to start the development environment.
You can view, edit, build or debug the code with [JCIDE](http://www.javacardos.com/tools/index.html?ws=github&prj=KeepassNFC#JCIDE), a powerful Javacard Integrated Development Environment.
You can use [pyApdutool](http://javacardos.com/tools/index.html?ws=github&prj=KeepassNFC#pyApduTool) to download and install the applet, please reference the [topic](http://javacardos.com/javacardforum/viewtopic.php?f=3&t=38&ws=github&prj=KeepassNFC) in the [JavaCardOS](http://javacardos.com/javacardforum/?ws=github&prj=KeepassNFC) for the operation detail.

### Gradle
The configuration gives you the ability to compile and convert easily of applet cap files, it has support for easy tests creation, including test coverage.
Also, it provides integration with Travis Continuous Integration platform, with the means to execute on both real cards and [JCardSim.org](https://jcardsim.org/) simulator.

This build configuration can be easily used with all the IDEs that gives integration with Gradle (IntelliJ, NetBeans, Eclipse...).

After recursively cloning the repository (to gather all the JavaCard SKDs), you can choose the desired JavaCard SDK to use by setting the `JCSDK` environment variable (by default it is empty, and the minimum required SDK version will be used). Then simply run
```
./gradlew buildJavaCard --info
```
to get the `.cap` file.

## Known compatibilities
Until [701cdfc](https://github.com/JavaCardSpot-dev/KeepassNFCApplet/commit/701cdfc89de7831d23bb91bf415e1e20b1ee72c4) it should work on [JC30M48](http://www.javacardos.com/store/javacard-jc30m48cr.php?ws=github&prj=KeepassNFC), the downloading and installation have been tested on this card.

## Maintainers
The original creator of the project is the [JavaCardOS](http://www.javacardos.com/) community.

As the initial [notice](#important) explains, this project will be maintained by students of the Masaryk University about until June 2018.

##  Usage
The Applet is able to decrypt the database at user’s wish with the use of password key stored in the card and IV sent by user.
The applet functionality can broadly classified into two categories:
(a) Card Configuration
(b) Card Usage

(a) Card functions during Configuration:

(i)   As a first step ,the user will send APDU to applet for generation of 2048b RSA key. The format of APDU is [0x75] - Generate Card Key. This method doesn’t expect any input, and if called it will reset the internal key, setting a flag indicating that the cipher isn’t initialized.   
(ii   The applet will then generate the key pair and send the output APDU contains three bytes indicating (1) the success of the operation and (2-3) the length of the internal key.
(iii) User will then request for public key from applet
(iv)  Applet will then send the public key back to user
(v)   User will then generate the password key using his password 
(vi)  User will then send the password key encrypted with public key to applet
(vii) Applet will then decrypt the password key with his private key and save it safely in EPROM using standard API

(b) Card functions during use:

  
(i)   User generates AES-128 Transacrtion key generated for each transaction and encrypts with public key it already have
(ii)  User then send this encrypted transaction key to applet
(iii) User then generates two IV (for transaction key and Password key) and sends to App
(iv)  App iniatises the cipher for password decryption and for encryption of transaction with IV and sent by user
(v)   User then sends the encrypted database to App
(vi)  App decrypts the database with Password key 
(vii) App then sends the retrieved data after doing encryption with Transaction Key to user
(viii)User then decrypts the recieved data with transaction key

The various APPDU formats that have been used during entire process above are as follows:-

(i)  [0x76] - Write To Scratch: this is the main communication method, since other commands relies on this method was previously called, 
with no checks. The format expected is to have the first two bytes indicating the offset at which the data to write starts, and from 
that offset the data will be copied until the end of the APDU buffer. The scratch area is a 260-bytes memory area allocated on RAM. No checks are done at all for emptiness, wrong offset value… The output APDU contains a success value (0x1) if everything went fine, otherwise a JavaCard exception will be raised.
(ii) [0x75] - Generate Card Key: this method doesn’t expect any input, and if called it will reset the internal key, setting a flag indicating that the cipher isn’t initialized. The output APDU contains three bytes indicating (1) the success of the operation and (2-3) the length of the internal key.

<<<<<<< HEAD
(ii)  [0x75] - Generate Card Key: this method doesn’t expect any input, and if called it will reset the internal key, setting a flag indicating that the cipher isn’t initialized. The output APDU contains three bytes indicating (1) the success of the operation and (2-3) the length of the internal key.

(iii) [0x71] - Set Password Key: the password key must be sent to the card encrypted with the card public key by the user. Hence, firstly this 
method expects the user to have already sent a Write To Scratch APDU with the encrypted password key. Now, this method will decrypt the scratch area to obtain password key (AES-128). 
=======
(iii) [0x71] - Set Password Key: the password key must be sent to the card encrypted with the card public key by the user. Hence, firstly this method expects the user to have already sent a Write To Scratch APDU with the encrypted password key. Now, this method will decrypt the scratch area to obtain password key (AES-128). 
>>>>>>> becca5227aa38a3aebe8fc338d9e98dfcec08108
No input is required, and the output contains one byte, always corresponding to the success value (0x1). If any problem occurs, the corresponding Java standard exception will be raised.

(iv)  [0x72] - Prepare Decryption: this method expects the user to have previously sent a Write To Scratch APDU with a transaction key (AES-128) encrypted with the public key of the card. This method will load this key into an internal variable (RAM), and it will initialize the ciphers for the transaction and for the password decryptions. The output APDU contains just the success/failure byte. 
The failure is set if the length of the incoming buffer data is not 32. Those bytes are the two IV components for the ciphers, 
in order: 16 bytes for the transaction cipher; 16 bytes for the password cipher. 
Both IVs are in plaintext and without MAC integrity.

## Security Issues found in the Applet:
1. Applet is using standard API of JavaCard cryptographic API rather than own implemented API.
Absence of state management: Presently, there is check for handling the error states during the failure of following important processes in the applet on card:
    Card Key pair generation and transfer of public key & its parameters (modulus & exponent) to user
    Initialization or Writing card keys in scratch Area
    Receiving password key in scratch area and its initialization with IV for decryption
    Receiving transaction key in scratch area and its initialization with IV for decryption
    Verify length of data to be decrypted 

2. Absence of intialisation and clearing of sensitive data: Sensitive data must be initialized at the beginning of each session and cleared when not needed anymore. The data can be cleared at the end of sessions using the CLEAR_ON_DESELECT directive and/or rewriting the content with random data/zeroes.
    
3. No use of custom exceptions: Missing try/catch and throw constructs (except for the standard INS_NOT_SUPPORTED) which helps to obtain useful information during development.

4. No fault induction check: Applet doesn’t check for invalid CLA in process(), and it only checks for valid CLA before switching on the instruction value, such that if CLA doesn’t match or an error occurs, the applet cannot manage the state. Also, other checks aren’t performed with redundancy to prevent the tampering with the instruction pointer of the smartcard.

5. No authentication and authorisation mechanisms: Applet doesn’t check in any way the authorisation to access the applet to use the password in the card, nor to edit the current configuration of the card. A method of authentication by the standard PIN implemented by JavaCard can be included, with particular attention on the first setup and erasing of data when problems occur.
    
6. No memory intialisation: Many primitives and byte arrays are not initialised, thus they may contain garbage values. These can be initialised to NULL.

## Cryptographic security issues (Attack surface)
1. AES-128 used is not considered too much secure due to key length of 128 bit. Hence, AES-256 can be used, also considering that AES-128 is not a supported algorithm by the main KeePass branch. Moreover, at least the others officially supported algorithms should be implemented by the applet. The managing of what “password” is, is left to the user application with reference to the official documentation.

2. Integrity and Protocol: Furthermore, there is no use of MAC to verify the integrity of data received or sent, and no real, well-tested protocol is used to ensure a secure communication channel between the user and the applet.

3. MITM: also, the absence of a real protocol of communication, exposes the security bug of a MITM attack during the sending of the public key to the user: it can be spoofed, gaining access to every future communication, both in reading and writing modes.

4. General Oracle: also, this exposes the ability for an attacker to spam the NFC channel in a bid to further attacks.

5. Padding Oracle Attack: all the AES-128 operations are implemented without padding, thus they’re not subject to this type of attack. However, the RSA algorithm used to encrypt the initial communication uses PKCS #1, that applies padding and is hence vulnerable to this class of attack during encryption/decryption.

6. Side channel attacks
The applet must be thoroughly tested if susceptible to side channel attacks, for example an adversary could perform a timing attack on calculations performed by RSA algorithm for generation of public and private key using modulus exponent form.
