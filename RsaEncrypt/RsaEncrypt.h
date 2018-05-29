//
//  RsaEncrypt.h
//  RsaEncrypt
//
//  Created by ZhangNing on 2018/5/16.
//  Copyright © 2018年 gmrz. All rights reserved.
//

#import <Foundation/Foundation.h>

@interface RsaEncrypt : NSObject

typedef NS_ENUM(OSStatus,RSA_SATAUS){
    
    RSA_SUCCESS = 0,
    RSA_FAILED = 1<<1,
    RSA_GET_PUBLICKEY_FAILED = 1<<2,
    RSA_GET_PRIVATEKEY_FAILED = 1<<3
};
//类方法,初始化设置公私钥Tag
+ (instancetype)sharedInstancePrivateTag:(NSData *)privateTag publicTag:(NSData *)publicTag;
//临时创建后临时更改公私钥tag
- (void) setPrivateTag:(NSData *)privateTag publicTag:(NSData *)publicTag;

//create Rsa generateKeys publicKey and privateKey
- (RSA_SATAUS)createRSA_generate_keys;

//encrypt someDataString use privateKey
- (RSA_SATAUS)encryptBeforeEncryptDataIn:(NSData *)encryptDataIn EncryptDataOut:(NSData **)encryptDataOut;


//decode SomeEncryptData use publicKey
- (RSA_SATAUS)decodeBeforeEncryptDataIn:(NSData *)encryptDataIn DecodeRncryptDataOut:(NSData **)decodeEncryptDataOut;

//del public and private keys Use KyesTag;
- (RSA_SATAUS)deleteRsaKeys;





@end
