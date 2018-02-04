const fs = require("fs");
const {createVerifySocket} = require("./");
const https = require('https');
const path = require("path");

var bundleCA = fs.readFileSync(path.join(__dirname,'test','cacert-2018-01-17.pem')); 


const verifyCertSocket = createVerifySocket();
verifyCertSocket.store.loadBundleCA(bundleCA);

const options = {
    hostname: 'incomplete-chain.badssl.com',
    port: 443,
    path: '/',
    method: 'GET',
    rejectUnauthorized: false
};

const req = https.request(options, (res) => {
    verifyCertSocket(res.socket,(err,value) =>{
        console.log("out",err,value);
    });
});

req.on('error', (e) => {
    console.error(e);
});
req.end();
