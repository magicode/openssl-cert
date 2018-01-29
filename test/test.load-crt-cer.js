
const path = require("path");
const fs = require("fs");

const {Cert,CertStore} = require("../");


var rootCrt = new Cert(fs.readFileSync(path.join(__dirname,'DigiCertGlobalRootCA.crt')));
var chainCrt = new Cert(fs.readFileSync(path.join(__dirname,'DigiCertSHA2SecureServerCA.crt')));
var certCrt = new Cert(fs.readFileSync(path.join(__dirname,'badssl.cer'))); 

var CAFileCrts = fs.readFileSync(path.join(__dirname,'cacert-2018-01-17.pem')); 


console.log(rootCrt.getSubject());
console.log(chainCrt.getSubject()); 
console.log(certCrt.getExtensions()); 

var store = new CertStore();

console.log(store.loadBundleCA(CAFileCrts));
//console.log(store.addCert(rootCrt));

console.log(store.verify(certCrt,[chainCrt],{ hostname: 'incomplete-chain.badssl.com' }));

// openssl verify -verify_hostname incomplete-chain.badssl.com -CAfile test/DigiCertGlobalRootCA.crt -untrusted  test/DigiCertSHA2SecureServerCA.crt  test/DigiCertSHA2SecureServerCA.crt
