#!/bin/bash
#Creates EC private key and associated certificate file using OpenSSL
#simon.moffatt@forgerock.com 23/01/18

clear
echo "Enter the output filename for the private key: (Eg my-key.pem)"
read private_key_filename
echo ""
echo "Creating EC 256 private key..."
openssl ecparam -name prime256v1 -genkey -noout -out $private_key_filename
echo ""
echo "Private key created at $private_key_filename and looks like the following:"
echo ""
openssl ec -in $private_key_filename -inform PEM -text
echo ""	
echo "Enter the output filename for the associated certificate: (Eg my-cert.pem)"
read cert_filename
echo ""
echo "Enter the CN for the certificate: (Eg CN=App)"
read cn
openssl req -new -x509 -key $private_key_filename -out $cert_filename -days 3650 -subj "/$cn"
echo ""	
echo "Certificate created at $cert_filename and looks like the following:"
echo ""
openssl x509 -in $cert_filename -text -noout
echo ""
echo "Done!"
echo ""


