#!/bin/bash

# Compile the applet, and produce a CAP file to install 
mvn clean && mvn compile && mvn org.apache.maven.plugins:maven-antrun-plugin:1.8:run

# java -jar ext/gp.jar --key-id 0 --key-ver 0 --key-enc 404142434445464748494a4b4c4d4e4f --key-mac 404142434445464748494a4b4c4d4e4f --key-dek 404142434445464748494a4b4c4d4e4f --uninstall target/scp10.cap --install target/scp10.cap
