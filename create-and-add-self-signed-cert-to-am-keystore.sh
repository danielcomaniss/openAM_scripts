#!/bin/bash
#Creates new self-signed cert and imports into AM JCEKS keystore
#simon.moffatt@forgerock.com

#Globals
ALIAS=newrsasigningkey
KEYSTORE=/home/smoff/am-nightly/openam/keystore.jceks
VALIDITY=360
KEYSIZE=2018

clear
#JAVE_HOME="/usr/java/jdk1.8.0_102"

#Creates new key with 1 year validity
#$JAVE_HOME/jre/bin/keytool -genkey -keyalg RSA -alias my-test-cert -keystore my-test-cert.jks -storepass password -validity 360 -keysize 2048
echo "Creating new keystore for alias $ALIAS ..."
keytool -genkey -keyalg RSA -alias $ALIAS -keystore $ALIAS.jks -validity $VALIDITY -keysize $KEYSIZE -storepass changeit
echo "Created alias $ALIAS..."
echo "Importing the new alias to $KEYSTORE ..."
#Adds existing jks stored private key into the existing AM jcecks keystore so you can sign SAML2 assertions etc
#$JAVE_HOME/jre/bin/keytool -importkeystore -srckeystore my-test-cert.jks -destkeystore ~/am5/openam/keystore.jceks -storetype jceks
keytool -importkeystore -srckeystore $ALIAS.jks -destkeystore $KEYSTORE -storetype jceks
echo "Done importing..."
echo "Clearing up..."
rm -rf $ALIAS.jks
echo "Done"

