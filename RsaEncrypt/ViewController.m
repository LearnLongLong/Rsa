//
//  ViewController.m
//  RsaEncrypt
//
//  Created by ZhangNing on 2018/5/16.
//  Copyright © 2018年 gmrz. All rights reserved.
//

#import "ViewController.h"
#import "RsaEncrypt.h"

@interface ViewController ()
@property (weak, nonatomic) IBOutlet UITextView *encryptDataStr;
@property (weak, nonatomic) IBOutlet UITextField *publicKeyTag;
@property (weak, nonatomic) IBOutlet UITextField *privateKeyTag;
@property (weak, nonatomic) IBOutlet UILabel *priTagLable;
@property (weak, nonatomic) IBOutlet UILabel *pubTagLable;

@property (nonatomic,copy)NSString *priTag;
@property (nonatomic,copy)NSString *pubTag;


@property (nonatomic,strong)RsaEncrypt *rsa;


@end

@implementation ViewController

- (void)viewDidLoad {
    [super viewDidLoad];
    
    
    [self.privateKeyTag addObserver:self forKeyPath:@"text" options:NSKeyValueObservingOptionNew context:nil];
    
    [self.publicKeyTag addObserver:self forKeyPath:@"text" options:NSKeyValueObservingOptionNew context:nil];
    
    
}

- (void)observeValueForKeyPath:(NSString *)keyPath ofObject:(id)object change:(NSDictionary<NSString *,id> *)change context:(void *)context {
    
    UITextField *tempField = object;
    
    switch (tempField.tag) {
        case 100:
        {
            NSString *newName = [change objectForKey:NSKeyValueChangeNewKey];
            self.priTag = newName;
        }
            
            break;
        case 200:
        {
            NSString *newName = [change objectForKey:NSKeyValueChangeNewKey];
            self.pubTag = newName;
        }
             
            break;
            
        default:
            break;
    }
    
    
}

- (IBAction)SaveTags:(id)sender {
    
    NSData *priTagData = [self.privateKeyTag.text dataUsingEncoding:NSUTF8StringEncoding];
    NSData *pubTagData = [self.publicKeyTag.text dataUsingEncoding:NSUTF8StringEncoding];
    
    
    _rsa = [RsaEncrypt sharedInstancePrivateTag:priTagData publicTag:pubTagData];
    
    self.priTagLable.text = self.privateKeyTag.text;
    self.pubTagLable.text = self.publicKeyTag.text;
    
    [self.privateKeyTag resignFirstResponder];
    [self.publicKeyTag resignFirstResponder];
    
    
}



- (IBAction)createRsaKeys:(id)sender {
    
    if (self.priTag!=nil && self.pubTag!=nil) {
        
        NSLog(@"priTag=%@ pubTag=%@",self.priTag,self.pubTag);
        
        
        RSA_SATAUS rsaStatus = [_rsa createRSA_generate_keys];
        
        [self checkStatus:rsaStatus];
        
    }else{
        
        
        [self showAlert:@"Tag为空"];
        
    }
    
    
}

- (IBAction)encryptData:(id)sender {
    
    if (![self.encryptDataStr.text isEqualToString:@""]) {
        
        NSLog(@"加密前数据=%@",self.encryptDataStr.text);
        
        NSData *data = [self.encryptDataStr.text dataUsingEncoding:NSUTF8StringEncoding];
        
        NSData *dataOut;
        
        RSA_SATAUS rsaStatus = [_rsa encryptBeforeEncryptDataIn:data EncryptDataOut:&dataOut];
        
        [self checkStatus:rsaStatus];
        
        NSString *base64String = [dataOut base64EncodedStringWithOptions:0];
        //转换为base64
        
        [self.encryptDataStr setText:base64String];
        
    }else{
        
        [self showAlert:@"加密数据为空"];
        
    }
    
    
}
- (IBAction)decrptData:(id)sender {
    
    if (![self.encryptDataStr.text isEqualToString:@""]) {
        
        NSData *decodedData = [self base64Decode:self.encryptDataStr.text];
        
        
        NSData *dataOut1 = nil;
        
        RSA_SATAUS rsaStatus = [_rsa decodeBeforeEncryptDataIn:decodedData DecodeRncryptDataOut:&dataOut1];
        
        [self checkStatus:rsaStatus];
        
        [self.encryptDataStr setText: [[NSString alloc] initWithData:dataOut1 encoding:NSUTF8StringEncoding]];
        
    }else{
        
        [self showAlert:@"解密数据为空"];
        
    }
    
    
    
}



- (IBAction)delKeys:(id)sender {
    
    RSA_SATAUS rsaStatus = [_rsa deleteRsaKeys];
    [self checkStatus:rsaStatus];
}

- (void)checkStatus:(RSA_SATAUS)rsaStatus{
    
    switch (rsaStatus) {
        case RSA_SUCCESS:
            [self showAlert:@"成功"];
            break;
        case RSA_FAILED:
            [self showAlert:@"失败"];
            break;
        case RSA_GET_PUBLICKEY_FAILED:
            [self showAlert:@"获取公钥失败"];
            break;
        case RSA_GET_PRIVATEKEY_FAILED:
            [self showAlert:@"获取私钥失败"];
            break;
            
        default:
            break;
    }
    
    
}

- (void)touchesBegan:(NSSet<UITouch *> *)touches withEvent:(UIEvent *)event{
    [self.encryptDataStr resignFirstResponder];
    [self.privateKeyTag resignFirstResponder];
    [self.publicKeyTag resignFirstResponder];
}

-(void)showAlert:(NSString *)msg
{
    dispatch_async(dispatch_get_main_queue(), ^{
        
        UIAlertView *alert = [[UIAlertView alloc] initWithTitle:nil message:msg delegate:nil cancelButtonTitle:@"确定" otherButtonTitles:nil];
        [alert show];
    });
}


-(void)checkTextField{
    if ([self.publicKeyTag.text isEqualToString:@""]&&self.publicKeyTag.text.length<=0&&[self.privateKeyTag.text isEqualToString:@""]&&self.privateKeyTag.text.length<=0) {
        
        [self showAlert:@"请输入KeyTag值"];
        
    }
    
}

- (NSData*) base64Decode:(NSString *)string
{
    unsigned long ixtext, lentext;
    unsigned char ch, inbuf[4], outbuf[4];
    short i, ixinbuf;
    Boolean flignore, flendtext = false;
    const unsigned char *tempcstring;
    NSMutableData *theData;
    
    if (string == nil) {
        return [NSData data];
    }
    
    ixtext = 0;
    
    tempcstring = (const unsigned char *)[string UTF8String];
    
    lentext = [string length];
    
    theData = [NSMutableData dataWithCapacity: lentext];
    
    ixinbuf = 0;
    
    while (true) {
        if (ixtext >= lentext){
            break;
        }
        
        ch = tempcstring [ixtext++];
        
        flignore = false;
        
        if ((ch >= 'A') && (ch <= 'Z')) {
            ch = ch - 'A';
        } else if ((ch >= 'a') && (ch <= 'z')) {
            ch = ch - 'a' + 26;
        } else if ((ch >= '0') && (ch <= '9')) {
            ch = ch - '0' + 52;
        } else if (ch == '+') {
            ch = 62;
        } else if (ch == '=') {
            flendtext = true;
        } else if (ch == '/') {
            ch = 63;
        } else {
            flignore = true;
        }
        
        if (!flignore) {
            short ctcharsinbuf = 3;
            Boolean flbreak = false;
            
            if (flendtext) {
                if (ixinbuf == 0) {
                    break;
                }
                
                if ((ixinbuf == 1) || (ixinbuf == 2)) {
                    ctcharsinbuf = 1;
                } else {
                    ctcharsinbuf = 2;
                }
                
                ixinbuf = 3;
                
                flbreak = true;
            }
            
            inbuf [ixinbuf++] = ch;
            
            if (ixinbuf == 4) {
                ixinbuf = 0;
                
                outbuf[0] = (inbuf[0] << 2) | ((inbuf[1] & 0x30) >> 4);
                outbuf[1] = ((inbuf[1] & 0x0F) << 4) | ((inbuf[2] & 0x3C) >> 2);
                outbuf[2] = ((inbuf[2] & 0x03) << 6) | (inbuf[3] & 0x3F);
                
                for (i = 0; i < ctcharsinbuf; i++) {
                    [theData appendBytes: &outbuf[i] length: 1];
                }
            }
            
            if (flbreak) {
                break;
            }
        }
    }
    
    return theData;
}

- (void)didReceiveMemoryWarning {
    [super didReceiveMemoryWarning];
    // Dispose of any resources that can be recreated.
}


@end
