//
//  RsaEncrypt.m
//  RsaEncrypt
//
//  Created by ZhangNing on 2018/5/16.
//  Copyright © 2018年 gmrz. All rights reserved.
//

#import "RsaEncrypt.h"

@interface RsaEncrypt()

@property(nonatomic,strong)NSData * publicTag;
@property(nonatomic,strong)NSData * privateTag;

@end

@implementation RsaEncrypt


- (void)setPrivateTag:(NSData *)privateTag publicTag:(NSData *)publicTag {
    
    self.publicTag = publicTag;
    self.privateTag = privateTag;
    
}


+ (instancetype)sharedInstancePrivateTag:(NSData *)privateTag publicTag:(NSData *)publicTag{
    static RsaEncrypt *_rsa = nil;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        _rsa = [[self alloc] init];
    });
    [_rsa setPrivateTag:privateTag publicTag:publicTag];
    
    return _rsa;
}


//create Rsa generateKeys publicKey and privateKey
- (RSA_SATAUS)createRSA_generate_keys{
    
    [self deleteRsaKeys];
    
    
    OSStatus sanityCheck = noErr;
    SecKeyRef publicKeyRef = NULL;
    SecKeyRef privateKeyRef = NULL;
    
    
    // Container dictionaries.
    NSMutableDictionary * privateKeyAttr = [NSMutableDictionary dictionaryWithCapacity:0];
    NSMutableDictionary * publicKeyAttr = [NSMutableDictionary dictionaryWithCapacity:0];
    NSMutableDictionary * keyPairAttr = [NSMutableDictionary dictionaryWithCapacity:0];
    
    // Set top level dictionary for the keypair.
    [keyPairAttr setObject:(__bridge id)kSecAttrKeyTypeRSA forKey:(__bridge id)kSecAttrKeyType];
    [keyPairAttr setObject:[NSNumber numberWithUnsignedInteger:2048] forKey:(__bridge id)kSecAttrKeySizeInBits];
    
    // Set the private key dictionary.
    [privateKeyAttr setObject:[NSNumber numberWithBool:YES] forKey:(__bridge id)kSecAttrIsPermanent];
    [privateKeyAttr setObject:_privateTag forKey:(__bridge id)kSecAttrApplicationTag];
    // See SecKey.h to set other flag values.
    
    // Set the public key dictionary.
    [publicKeyAttr setObject:[NSNumber numberWithBool:YES] forKey:(__bridge id)kSecAttrIsPermanent];
    [publicKeyAttr setObject:_publicTag forKey:(__bridge id)kSecAttrApplicationTag];
    // See SecKey.h to set other flag values.
    
    // Set attributes to top level dictionary.
    [keyPairAttr setObject:privateKeyAttr forKey:(__bridge id)kSecPrivateKeyAttrs];
    [keyPairAttr setObject:publicKeyAttr forKey:(__bridge id)kSecPublicKeyAttrs];
    
    // SecKeyGeneratePair returns the SecKeyRefs just for educational purposes.
    sanityCheck = SecKeyGeneratePair((__bridge CFDictionaryRef)keyPairAttr, &publicKeyRef, &privateKeyRef);
    
    
    return sanityCheck!=noErr?RSA_FAILED:RSA_SUCCESS;

    
    
}

//encrypt someDataString use privateKey
- (RSA_SATAUS)encryptBeforeEncryptDataIn:(NSData *)encryptDataIn EncryptDataOut:(NSData **)encryptDataOut{
    
    SecKeyRef publicKeyRef = NULL;
    
    
    RSA_SATAUS getKyes_Staus= [self getKeyUseKeyTag:self.publicTag SecKeyRef:&publicKeyRef];
    
    if (getKyes_Staus!=RSA_SUCCESS) {
        
        return RSA_GET_PUBLICKEY_FAILED;
    }
    
    size_t cipherBufferSize = SecKeyGetBlockSize(publicKeyRef);
    uint8_t *cipherBuffer = malloc(cipherBufferSize * sizeof(uint8_t));
    memset((void *)cipherBuffer, 0*0, cipherBufferSize);

 
    
    OSStatus status = SecKeyEncrypt(publicKeyRef,
                                    kSecPaddingPKCS1,
                                    (const uint8_t *)[encryptDataIn bytes],
                                    [encryptDataIn length],
                                    cipherBuffer,
                                    &cipherBufferSize);
    
    if (status==noErr) {
        
        NSData *encryptedBytes = [NSData dataWithBytes:(const void *)cipherBuffer length:cipherBufferSize];
        
        *encryptDataOut = encryptedBytes;
        
        if (cipherBuffer) free(cipherBuffer);
        
    }else{
        
        if (cipherBuffer) {
            free(cipherBuffer);
        }
        
    }
    
    
    return status!=noErr?RSA_FAILED:RSA_SUCCESS;
    
}


//decode SomeEncryptData use publicKey
- (RSA_SATAUS)decodeBeforeEncryptDataIn:(NSData *)encryptDataIn DecodeRncryptDataOut:(NSData **)decodeEncryptDataOut{
    
    SecKeyRef privateKeyRef = NULL;
    
    RSA_SATAUS getKyes_Staus = [self getKeyUseKeyTag:self.privateTag SecKeyRef:&privateKeyRef];
    
    if (getKyes_Staus!=RSA_SUCCESS) {
        
        return RSA_GET_PRIVATEKEY_FAILED;
    }
    
    
    NSData *wrappedSymmetricKey = encryptDataIn;
    size_t cipherBufferSize = SecKeyGetBlockSize(privateKeyRef);
    size_t keyBufferSize = [wrappedSymmetricKey length];
    
    NSMutableData *bits = [NSMutableData dataWithLength:keyBufferSize];
    
    
    OSStatus sanityCheck = SecKeyDecrypt(privateKeyRef,
                                         kSecPaddingPKCS1,
                                         (const uint8_t *) [wrappedSymmetricKey bytes],
                                         cipherBufferSize,
                                         [bits mutableBytes],
                                         &keyBufferSize);
    
    [bits setLength:keyBufferSize];
    
    if (bits!=nil) {
        *decodeEncryptDataOut = bits;
        
    }
    
    
    
    return sanityCheck!=noErr?RSA_FAILED:RSA_SUCCESS;
    
    
    
}

//del public and private keys Use KyesTag;
- (RSA_SATAUS)deleteRsaKeys{
    
    
    
    OSStatus sanityCheck = noErr;
    NSMutableDictionary * queryPublicKey        = [NSMutableDictionary dictionaryWithCapacity:0];
    NSMutableDictionary * queryPrivateKey       = [NSMutableDictionary dictionaryWithCapacity:0];
   
    
    // Set the public key query dictionary.
    [queryPublicKey setObject:(__bridge id)kSecClassKey forKey:(__bridge id)kSecClass];
    [queryPublicKey setObject:_publicTag forKey:(__bridge id)kSecAttrApplicationTag];
    [queryPublicKey setObject:(__bridge id)kSecAttrKeyTypeRSA forKey:(__bridge id)kSecAttrKeyType];
    
    // Set the private key query dictionary.
    [queryPrivateKey setObject:(__bridge id)kSecClassKey forKey:(__bridge id)kSecClass];
    [queryPrivateKey setObject:_privateTag forKey:(__bridge id)kSecAttrApplicationTag];
    [queryPrivateKey setObject:(__bridge id)kSecAttrKeyTypeRSA forKey:(__bridge id)kSecAttrKeyType];
    
    sanityCheck = SecItemDelete((__bridge CFDictionaryRef)queryPrivateKey);
    
    
    sanityCheck = SecItemDelete((__bridge CFDictionaryRef)queryPublicKey);
    
    return sanityCheck!=noErr?RSA_FAILED:RSA_SUCCESS;
    
    
}








//get public Keys
- (RSA_SATAUS)getKeyUseKeyTag:(NSData *)KeyTag SecKeyRef:(SecKeyRef *)secKeyRef {
    
    OSStatus resultCode = noErr;
    
    NSMutableDictionary * queryPublicKey = [NSMutableDictionary dictionaryWithCapacity:0];
    
    // Set the public key query dictionary.
    [queryPublicKey setObject:(__bridge id)kSecClassKey forKey:(__bridge id)kSecClass];
    
    [queryPublicKey setObject:KeyTag forKey:(__bridge id)kSecAttrApplicationTag];
    
    [queryPublicKey setObject:(__bridge id)kSecAttrKeyTypeRSA forKey:(__bridge id)kSecAttrKeyType];
    
    [queryPublicKey setObject:[NSNumber numberWithBool:YES] forKey:(__bridge id)kSecReturnRef];
    
    // Get the key.
    resultCode = SecItemCopyMatching((__bridge CFDictionaryRef)queryPublicKey, (CFTypeRef *)secKeyRef);
    //NSLog(@"getPublicKey: result code: %ld", resultCode);
    
    if(resultCode != noErr)
    {
        secKeyRef = NULL;
        
    }
    queryPublicKey =nil;
    
    return resultCode!=noErr?RSA_FAILED:RSA_SUCCESS;
    
    
}

@end
