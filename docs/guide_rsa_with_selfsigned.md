wip

## RSA Keys generate selfsigned

openssl genrsa -out cert/id_rsa 4096
openssl rsa -in cert/id_rsa -RSAPublicKey_out -out  cert/id_rsa.pub


openssl rsa -in cert/id_rsa -pubout -out cert/id_rsa.pub