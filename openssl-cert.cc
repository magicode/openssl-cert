#include <nan.h>
#include "node.h"
#include "v8.h"

#include <node_buffer.h>
#include <node_object_wrap.h>

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <map>
#include <list>
 
#include <openssl/ssl.h>
#include <openssl/err.h>

#include <openssl/x509.h>
#include <openssl/x509v3.h>


#define NS(s) Nan::New(s).ToLocalChecked()
 
using namespace node;
using namespace v8;
using v8::String;


class Cert: public ObjectWrap {
    public:
    X509 *cert = NULL;
    static inline Nan::Persistent<v8::Function> & constructor() {
        static Nan::Persistent<v8::Function> my_constructor;
        return my_constructor;
    }
  
    Cert(X509 *_cert){
        cert = _cert;
    }
    
    ~Cert(){
        if(cert)
            X509_free(cert);
    }
    
    static NAN_METHOD(New){
        Nan::HandleScope();
          
        if (!info.IsConstructCall()) {
            const int argc = 1;
            v8::Local<v8::Value> argv[argc] = {info[0]};
            v8::Local<v8::Function> cons = Nan::New(constructor());
            info.GetReturnValue().Set(cons->NewInstance(argc, argv));
        }
        
        v8::Local<v8::Value> val = info[0];
        
        X509 *cert = NULL;
        
        unsigned char *data;
		size_t data_len;
		 
		
		if (node::Buffer::HasInstance(val)) {
			data = (unsigned char *)node::Buffer::Data(val);
			data_len = node::Buffer::Length(val);
		} else
			return Nan::ThrowError("first no buffer");
        
        if(data_len < 2)
            return Nan::ThrowError("invalid buffer");
        		
		BIO *bio = BIO_new_mem_buf(data, data_len);
        
		if(!bio) return Nan::ThrowError("error CERT"); 
		
		if(data[0] == 0x30 && data[1] == 0x82){
		    cert = d2i_X509_bio(bio, NULL);
		}else{
		    cert = PEM_read_bio_X509(bio, NULL, NULL, NULL); 
		}
		
		BIO_free_all(bio);
		
		if(!cert) return Nan::ThrowError("error load CA CERT");
		
        Cert* obj = new Cert(cert);
        obj->Wrap(info.This());
        
        //obj->Ref();
        return info.GetReturnValue().Set(info.This());
    }

    static NAN_METHOD(GetIssuer){
        Nan::HandleScope();
        
        Cert* obj = ObjectWrap::Unwrap<Cert>(info.Holder());
        
        info.GetReturnValue().Set(ParseName(X509_get_issuer_name(obj->cert)));
    }

    static NAN_METHOD(GetSubject){
        Nan::HandleScope();
        
        Cert* obj = ObjectWrap::Unwrap<Cert>(info.Holder());
        
        info.GetReturnValue().Set(ParseName(X509_get_subject_name(obj->cert)));
    }
    
    
    static NAN_METHOD(GetExtensions){
        Nan::HandleScope();
        
        Cert* obj = ObjectWrap::Unwrap<Cert>(info.Holder()); 
        // Extensions
        Local<Object> extensions = Nan::New<Object>();
        
        STACK_OF(X509_EXTENSION) *exts = obj->cert->cert_info->extensions;
        int num_of_exts;
        int index_of_exts;
        if (exts) {
            num_of_exts = sk_X509_EXTENSION_num(exts);
        } else {
            num_of_exts = 0;
        }
        
        // IFNEG_FAIL(num_of_exts, "error parsing number of X509v3 extensions.");
        
        for (index_of_exts = 0; index_of_exts < num_of_exts; index_of_exts++) {
            X509_EXTENSION *ext = sk_X509_EXTENSION_value(exts, index_of_exts);
            // IFNULL_FAIL(ext, "unable to extract extension from stack");
            ASN1_OBJECT *obj = X509_EXTENSION_get_object(ext);
            // IFNULL_FAIL(obj, "unable to extract ASN1 object from extension");
        
            BIO *ext_bio = BIO_new(BIO_s_mem());
            // IFNULL_FAIL(ext_bio, "unable to allocate memory for extension value BIO");
            if (!X509V3_EXT_print(ext_bio, ext, 0, 0)) {
              M_ASN1_OCTET_STRING_print(ext_bio, ext->value);
            }
        
            BUF_MEM *bptr;
            BIO_get_mem_ptr(ext_bio, &bptr);
            BIO_set_close(ext_bio, BIO_CLOSE);
        
            char *data = new char[bptr->length + 1];
            BUF_strlcpy(data, bptr->data, bptr->length + 1);
            BIO_free(ext_bio);
        
            unsigned nid = OBJ_obj2nid(obj);
            if (nid == NID_undef) {
              char extname[100];
              OBJ_obj2txt(extname, 100, (const ASN1_OBJECT *) obj, 1);
              Nan::Set(extensions,NS(extname),NS(data));
        
            } else {
              const char *c_ext_name = OBJ_nid2ln(nid);
              // IFNULL_FAIL(c_ext_name, "invalid X509v3 extension name");
              Nan::Set(extensions,NS((char*)c_ext_name),NS(data));
            }
            delete[] data;
        }
        
        info.GetReturnValue().Set(extensions);
    }
    
    
    static v8::Local<v8::Object> ParseName(X509_NAME *name){
        v8::Local<v8::Object> out = Nan::New<v8::Object>();
        int i, length;
        
        ASN1_OBJECT *entry;
        
        unsigned char *value;
        char buf[255];
        length = X509_NAME_entry_count(name);
        
        for (i = 0; i < length; i++) {
            entry = X509_NAME_ENTRY_get_object(X509_NAME_get_entry(name, i));
            OBJ_obj2txt(buf, 255, entry, 0);
            value = ASN1_STRING_data(X509_NAME_ENTRY_get_data(X509_NAME_get_entry(name, i)));
            Nan::Set(out, NS(buf), NS((const char*) value));
        }
        
        return out;
    }
    
    
    static NAN_MODULE_INIT(Initialize) {
        v8::Local<v8::FunctionTemplate> tpl = Nan::New<v8::FunctionTemplate>(New);
        tpl->SetClassName(Nan::New("Cert").ToLocalChecked());
        tpl->InstanceTemplate()->SetInternalFieldCount(1);
        
        SetPrototypeMethod(tpl, "getSubject", GetSubject);
        SetPrototypeMethod(tpl, "getIssuer", GetIssuer);
        SetPrototypeMethod(tpl, "getExtensions", GetExtensions);
        
        constructor().Reset(Nan::GetFunction(tpl).ToLocalChecked());
        
        Nan::Set(target, Nan::New("Cert").ToLocalChecked(), Nan::GetFunction(tpl).ToLocalChecked());
    }
    
};

class CertStore : public ObjectWrap {
    public:
    
    X509_STORE *store = NULL;
    
    static inline Nan::Persistent<v8::Function> & constructor() {
        static Nan::Persistent<v8::Function> my_constructor;
        return my_constructor;
    }
  
    CertStore(){
        store = X509_STORE_new();
        OpenSSL_add_all_algorithms(); 
    }
    
    ~CertStore(){
        
    }
    
    static NAN_METHOD(New){
        Nan::HandleScope();
          
        if (!info.IsConstructCall()) {
            const int argc = 1;
            v8::Local<v8::Value> argv[argc] = {info[0]};
            v8::Local<v8::Function> cons = Nan::New(constructor());
            info.GetReturnValue().Set(cons->NewInstance(argc, argv));
        }
        
        CertStore* obj = new CertStore();
        obj->Wrap(info.This());
        //obj->Ref();
        return info.GetReturnValue().Set(info.This());
    }
    
    static NAN_METHOD(AddCert){
        Nan::HandleScope();
          
        CertStore* obj = ObjectWrap::Unwrap<CertStore>(info.Holder());
        
        Cert* ocert = ObjectWrap::Unwrap<Cert>(info[0]->ToObject()); 
        
        BIO *bp = BIO_new(BIO_s_mem());
        
        if(i2d_X509_bio(bp,ocert->cert) == 0)
            return Nan::ThrowError("error addCert");

        X509* newCert = d2i_X509_bio(bp,NULL);
        
        if( newCert == NULL)
            return Nan::ThrowError("error addCert");
        
        X509_STORE_add_cert(obj->store, newCert);
        X509_free(newCert);
        BIO_free(bp);
        
        info.GetReturnValue().Set(Nan::New(true));
    }
    
    static NAN_METHOD(Verify){
        Nan::HandleScope();
        
        const char *error = NULL;
        STACK_OF(X509) *untrusted = NULL;
        
        CertStore* obj = ObjectWrap::Unwrap<CertStore>(info.Holder());
        
        Cert* firstCert = ObjectWrap::Unwrap<Cert>(info[0]->ToObject());
        
        Local<Array> array = Local<Array>::Cast(info[1]); //args[0] holds the first argument

        for (unsigned int i = 0; i < array->Length(); i++ ) {
            if (Nan::Has(array, i).FromJust()) {
                //assuming the argument is an array of 'double' values, for any other type the following line will be changed to do the conversion
                Cert* chainCert = ObjectWrap::Unwrap<Cert>(Nan::Get(array, i).ToLocalChecked()->ToObject());
                if(chainCert->cert){
                    if(!untrusted)
                        untrusted = sk_X509_new_null();
                    sk_X509_push(untrusted, chainCert->cert);
                }
            }
        }
        
        Local<Object> opts = info[2]->ToObject();
        

        X509_STORE_CTX *store_ctx = NULL;
        
        store_ctx = X509_STORE_CTX_new();
        
        X509_STORE_CTX_init(store_ctx, obj->store, firstCert->cert, untrusted);
        
        int ret = X509_verify_cert(store_ctx);
        
        X509_STORE_CTX_free(store_ctx);
        sk_X509_free(untrusted);
        
        
        
        if (ret <= 0) {
            error =  X509_verify_cert_error_string(store_ctx->error);
            return Nan::ThrowError(error);
        }
        
        
        if(opts->Has(NS("hostname"))){
            Nan::Utf8String host(opts->Get(NS("hostname"))->ToString());
            if(!*host) return Nan::ThrowError("error hostname");
            int ret = X509_check_host(firstCert->cert,*host,0,0,NULL);
            if(ret <= 0){
                return Nan::ThrowError("mistake hostname");
            } 
        }
        
        
        info.GetReturnValue().Set(Nan::New(true));
    }
    static NAN_MODULE_INIT(Initialize) {
        v8::Local<v8::FunctionTemplate> tpl = Nan::New<v8::FunctionTemplate>(New);
        tpl->SetClassName(Nan::New("CertStore").ToLocalChecked());
        tpl->InstanceTemplate()->SetInternalFieldCount(1);
        
        SetPrototypeMethod(tpl, "addCert", AddCert); 
        SetPrototypeMethod(tpl, "verify", Verify); 
        
        constructor().Reset(Nan::GetFunction(tpl).ToLocalChecked());
        
        Nan::Set(target, Nan::New("CertStore").ToLocalChecked(), Nan::GetFunction(tpl).ToLocalChecked());
    }
    
};


NAN_MODULE_INIT(init){
    Cert::Initialize(target);
    CertStore::Initialize(target);
}

NODE_MODULE(opensslcert, init);