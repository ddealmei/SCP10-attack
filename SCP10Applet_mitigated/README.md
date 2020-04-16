# SCP10Applet

Partial JavaCard implementation of SCP10 key exchange, following [GlobalPlatform Card Specification v2.3.1 (March 2018)](https://globalplatform.org/specs-library/card-specification-v2-3-1/).

This repository shouldcontains everything you need to build the applet, and deploy it on a smart card.

## Build

This applet has been developped using [JCDKv3.0.4](ext/jc304_kit).

It can be build using maven. You can either run the `[build.sh](build.sh)` scritp or run the following commands:
```bash
mvn clean
mvn compile
mvn org.apache.maven.plugins:maven-antrun-plugin:1.8:run
```

This will compile the code, and convert it into a CAP file, saved in the `target` repository.

## Deployment on a smart card

You can install the CAP file on a smart card using `gp.jar`. To do so you will need you smart card keys. The following instruction assume you are using the default keys, change it accordingly if needed:
```java
java -jar ext/gp.jar --uninstall target/scp10.cap --install target/scp10.cap
```

## Mitigations

This applet differs from the other by the mitigations we added:
* **Key isolation**: instead of using the same RSA key pair to ensure both authentication and confidentiality, two separate keys are used. This prevent an attacker to abuse a vulnerability indecryption to forge a valid signature (and the other way around, also it is less likely).
* **Better RSA padding**: instead of a PKCS#1v1.5-like padding, we use OAEP for encryption. This prevent an attacker to exploit the attacks we presented in our paper.
* **e=65537**: Not mandatory given the previous mitigations, but we wanted to prove that using a safe public exponent does not induce a significant overhead.
