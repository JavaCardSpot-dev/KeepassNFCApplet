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
It should work on [JC30M48](http://www.javacardos.com/store/javacard-jc30m48cr.php?ws=github&prj=KeepassNFC), the downloading and installation have been tested on this card.

##  Usage
The Applet is able to decrypt the database at user’s wish with the use of password key stored in the card and IV sent by user.
The applet functionality can broadly classified into two categories:
(a) Card Configuration
(b) Card Usage

## Maintainers
The original creator of the project is the [JavaCardOS](http://www.javacardos.com/) community.

As the initial [notice](#important) explains, this project will be maintained by students of the Masaryk University about until June 2018.
