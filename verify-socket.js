module.exports = require("./openssl-cert.js");

const {Cert,CertStore} = module.exports;
const async = require("async");
const LRU = require("lru-cache");
const http = require('http');
const url = require("url");
 
function createVerifySocket(){

    var store = new CertStore(); 
    
    const cacheCertIntermediate = LRU({ max: 500 }); 
    
    function verifyCertSocket(socket,callback) {
        if(!socket.authorized){
            if(socket.authorizationError == 'UNABLE_TO_VERIFY_LEAF_SIGNATURE'){
                var currCert = socket.getPeerCertificate(true); 
                autoVerify(currCert,socket._host,callback);
            }else{
                callback(socket.authorizationError,false);
            }
        }else{
            callback(null,true);
        }
    }
    
    function autoVerify(cert , hostname ,callback){
        
        var certsList = [];
        var certsKV = {};
        
        function loadCert(raw){
            var c = null;
            try {
                c = new Cert(raw);
            } catch (e) {
                return null;
            }
            
            var accessURI = undefined;
            try {
                accessURI = c.getExtensions()['Authority Information Access'].split(/[\n+]/).find(s => s.startsWith('CA Issuers - URI:')).substr('CA Issuers - URI:'.length);
            } catch (e) {}
            var issuerCN = undefined;
            try {
                issuerCN = c.getIssuer().commonName;
            } catch (e) {}
            
            var subjectCN = null;
            try {
                subjectCN = c.getSubject().commonName;
            } catch (e) {}
            
            var item = { accessURI , issuerCN , subjectCN , cert: c };
            certsList.push(item);
            certsKV[item.subjectCN] = item;
            
            console.log(item);
        }
        
        for(var i = 0; i <= 10; i++){
            if(!cert) break;
            if(cert.raw) loadCert(cert.raw);
            cert = cert.issuerCertificate == cert ? undefined : cert.issuerCertificate;
        } 
        
        var certIncomplete = [];
        
        for (let i = certsList.length - 1; i >= 0; i--) {
            let item = certsList[i];
            
            if(item.accessURI && item.issuerCN && !certsKV[item.issuerCN]){
                var cacheCert = cacheCertIntermediate.get(item.accessURI);
                if(cacheCert){
                    certsList.splice( i + 1, 0, cacheCert);
                }else{
                    certIncomplete.push(item);
                }
            }
        }
        
        if(!certIncomplete.length) return verify();
        
        async.each(certIncomplete, (item, next) => {
            getUrl(item.accessURI, (err, data) => {
                if (err || data.length < 10) return next();
                
                let downCert = loadCert(data);
                if (!downCert || !downCert.subjectCN) return next();  
                cacheCertIntermediate.set(item.accessURI,downCert);
                
                var index = certsList.indexOf(item);
                if(index > -1){
                    certsList.splice( index + 1, 0, downCert);
                }
                next();
            });
        }, () => {
            verify();
        });
        
        
        function verify(){
            
            if(!certsList) return callback(new Error('empty certs'));
            
            var val = false;
            try {
                val = store.verify(certsList[0].cert,certsList.map(i => i.cert),{ hostname: hostname });
            } catch (e) {
                return  callback(e);
            }
            
            return  callback(null,val);
        }
    }
    
    function getUrl(link,callback){
        
        var options = {};
        try {
            options = url.parse(link);
        } catch (e) {
            return callback(e);
        }
    
        options.timeout = 3000;
        
        http.get(options, (res) => {
            
            var buffs = [];
            var buffsTotal = 0;
            
            res.on('data', (chunk) => {
                buffsTotal += chunk.length;
                if(buffsTotal > 30000){
                    res.socket.destroy();
                }
                buffs.push(chunk);
            });
            res.on('end', () => {
                var buf = Buffer.concat(buffs);
                callback(null,buf);
            });
        }).on('error', (e) => {
            callback(e);
        });
    }
    
    verifyCertSocket.store = store;
    verifyCertSocket.cacheCertIntermediate = cacheCertIntermediate;
    
    return verifyCertSocket;
}

module.exports.createVerifySocket = createVerifySocket;