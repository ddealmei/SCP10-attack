# SCP10Applet

Partial JavaCard implementation of SCP10 key exchange, following [GlobalPlatform Card Specification v2.3.1 (March 2018)](https://globalplatform.org/specs-library/card-specification-v2-3-1/).

This repository shouldcontains everything you need to build the applet, and deploy it on a smart card.

## Build

This applet has been developped using [JCDKv2.1.1](ext/jc212_kit).

It can be build using maven. You can either run the `[build.sh](build.sh)` scritp or run the following commands:
```bash
mvn clean
mvn compile
mvn org.apache.maven.plugins:maven-antrun-plugin:1.8:run
```

This will compile the code, and convert it into a CAP file, saved in the `target` repository.

## Deployment on a smart card

You can install the CAP file on a smart card using `gp.jar`. To do so you will need you smart card keys. The following instruction assume you are using the same key, change it accordingly if needed:
```java
java -jar ext/gp.jar --key-id 0 --key-ver 0 --key-enc 404142434445464748494a4b4c4d4e4f --key-mac 404142434445464748494a4b4c4d4e4f --key-dek 404142434445464748494a4b4c4d4e4f --uninstall target/scp10.cap --install target/scp10.cap
```
