#!/bin/bash

# Compile the applet, and produce a CAP file to install 
mvn clean && mvn compile && mvn org.apache.maven.plugins:maven-antrun-plugin:1.8:run

# java -jar ext/gp.jar --uninstall target/scp10.cap --install target/scp10.cap