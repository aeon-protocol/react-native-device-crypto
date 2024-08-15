#import <Security/Security.h>
#import <React/RCTConvert.h>
#import <React/RCTBridge.h>
#import <React/RCTUtils.h>
#import <LocalAuthentication/LAContext.h>
#import <LocalAuthentication/LAError.h>
#import <UIKit/UIKit.h>
#import "DeviceCrypto.h"

@implementation DeviceCrypto
@synthesize bridge = _bridge;

RCT_EXPORT_MODULE()

#pragma mark - DeviceCrypto

- (void)dealloc {
  if (_privateKeyRef) {
    CFRelease(_privateKeyRef);
    _privateKeyRef = nil;
  }
}

#define kKeyType @"keyType"
#define kAccessLevel @"accessLevel"
#define kInvalidateOnNewBiometry @"invalidateOnNewBiometry"
#define kAuthenticatePrompt @"biometryDescription"
#define kAuthenticationRequired @"Authentication is required"

typedef NS_ENUM(NSUInteger, KeyType) {
    ASYMMETRIC = 0,
    SYMMETRIC = 1,
};

typedef NS_ENUM(NSUInteger, AccessLevel) {
  ALWAYS = 0,
  UNLOCKED_DEVICE = 1,
  AUTHENTICATION_REQUIRED = 2,
};

- (SecKeyRef) getPublicKeyRef:(nonnull NSData*) alias
{
  NSDictionary *query = @{
    (id)kSecClass:               (id)kSecClassKey,
    (id)kSecAttrKeyClass:        (id)kSecAttrKeyClassPublic,
    (id)kSecAttrLabel:           @"publicKey",
    (id)kSecAttrApplicationTag:  (id)alias,
    (id)kSecReturnRef:           (id)kCFBooleanTrue,
  };
  
  CFTypeRef resultTypeRef = NULL;
  OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef) query, &resultTypeRef);
  if (status == errSecSuccess) {
    return (SecKeyRef)resultTypeRef;
  } else if (status == errSecItemNotFound) {
    return nil;
  } else
  [NSException raise:@"Unexpected OSStatus" format:@"Status: %i", (int)status];
  return nil;
}

- (NSData *)getPublicKeyBits:(nonnull NSData*)alias
{
    NSDictionary *query = @{
        (id)kSecClass:               (id)kSecClassKey,
        (id)kSecAttrKeyClass:        (id)kSecAttrKeyClassPublic,
        (id)kSecAttrLabel:           @"publicKey",
        (id)kSecAttrApplicationTag:  (id)alias,
        (id)kSecReturnData:          (id)kCFBooleanTrue,
        (id)kSecReturnRef:           (id)kCFBooleanTrue,
    };

    SecKeyRef keyRef;
    OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)query, (CFTypeRef *)&keyRef);
    if (status == errSecSuccess) {
        // Get the data associated with kSecValueData from the returned dictionary
        CFDataRef dataRef = (CFDataRef)CFDictionaryGetValue((CFDictionaryRef)keyRef, kSecValueData);
        if (dataRef) {
            return (__bridge NSData *)dataRef;
        } else {
            return nil;
        }
    } else if (status == errSecItemNotFound) {
        return nil;
    } else {
        [NSException raise:@"Unexpected OSStatus" format:@"Status: %i", status];
    }
    return nil;
}

- (NSString*)getPublicKeyBase64Encoded:(nonnull NSData *)alias {
    NSData *publicKeyBits = [self getPublicKeyBits:alias];

    if (publicKeyBits == nil) {
        return nil;
    }

    NSString *base64EncodedPublicKey = [publicKeyBits base64EncodedStringWithOptions:0];
    return base64EncodedPublicKey;
}

- (bool) savePublicKeyFromRef:(nonnull SecKeyRef)publicKeyRef withAlias:(nonnull NSData*) alias
{
  NSDictionary* attributes =
  @{
    (id)kSecClass:              (id)kSecClassKey,
    (id)kSecAttrKeyClass:       (id)kSecAttrKeyClassPublic,
    (id)kSecAttrLabel:          @"publicKey",
    (id)kSecAttrApplicationTag: (id)alias,
    (id)kSecValueRef:           (__bridge id)publicKeyRef,
    (id)kSecAttrIsPermanent:    (id)kCFBooleanTrue,
  };
  
  OSStatus status = SecItemAdd((CFDictionaryRef)attributes, nil);
  while (status == errSecDuplicateItem)
  {
    status = SecItemDelete((CFDictionaryRef)attributes);
  }
  status = SecItemAdd((CFDictionaryRef)attributes, nil);
  
  return true;
}

- (bool) deletePublicKey:(nonnull NSData*) alias
{
  NSDictionary *query = @{
    (id)kSecClass:               (id)kSecClassKey,
    (id)kSecAttrKeyClass:        (id)kSecAttrKeyClassPublic,
    (id)kSecAttrLabel:           @"publicKey",
    (id)kSecAttrApplicationTag:  (id)alias,
  };
  OSStatus status = SecItemDelete((CFDictionaryRef) query);
  while (status == errSecDuplicateItem)
  {
    status = SecItemDelete((CFDictionaryRef) query);
  }
  return true;
}

- (SecKeyRef) getPrivateKeyRef:(nonnull NSData*)alias withMessage:(NSString *)authPromptMessage
{
  NSString *authenticationPrompt = @"Authenticate to retrieve secret";
  if (authPromptMessage) {
    authenticationPrompt = authPromptMessage;
  }
  NSDictionary *query = @{
    (id)kSecClass:               (id)kSecClassKey,
    (id)kSecAttrKeyClass:        (id)kSecAttrKeyClassPrivate,
    (id)kSecAttrLabel:           @"privateKey",
    (id)kSecAttrApplicationTag:  (id)alias,
    (id)kSecReturnRef:           (id)kCFBooleanTrue,
    (id)kSecUseOperationPrompt:  authenticationPrompt,
  };
  
  CFTypeRef resultTypeRef = NULL;
  OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef) query,  (CFTypeRef *)&resultTypeRef);
  if (status == errSecSuccess)
    return (SecKeyRef)resultTypeRef;
  else if (status == errSecItemNotFound)
    return nil;
  else
    [NSException raise:@"E1715: Unexpected OSStatus" format:@"Status: %i", (int)status];
  return nil;
}


//putting in separate function to make user only do one face scan for multiple operations
- (SecKeyRef)retrievePrivateKeyRef:(nonnull NSData *)alias withMessage:(NSString *)authMessage error:(NSError **)error {
    @try {
        return [self getPrivateKeyRef:alias withMessage:authMessage];
    } @catch (NSException *exception) {
        if (error) {
            *error = [NSError errorWithDomain:@"PrivateKeyRetrievalError"
                                         code:1001
                                     userInfo:@{NSLocalizedDescriptionKey: exception.description}];
        }
        return nil;
    }
}

- (bool) deletePrivateKey:(nonnull NSData*) alias
{
  NSDictionary *query = @{
    (id)kSecClass:               (id)kSecClassKey,
    (id)kSecAttrKeyClass:        (id)kSecAttrKeyClassPrivate,
    (id)kSecAttrLabel:           @"privateKey",
    (id)kSecAttrApplicationTag:  (id)alias,
  };
  OSStatus status = SecItemDelete((CFDictionaryRef) query);
  while (status == errSecDuplicateItem)
  {
    status = SecItemDelete((CFDictionaryRef) query);
  }
  return true;
}

- (BOOL) hasBiometry {
  NSError *aerr = nil;
  LAContext *context = [[LAContext alloc] init];
  return [context canEvaluatePolicy:LAPolicyDeviceOwnerAuthenticationWithBiometrics error:&aerr];
}

- (BOOL) hasPassCode {
  NSError *aerr = nil;
  LAContext *context = [[LAContext alloc] init];
  return [context canEvaluatePolicy:LAPolicyDeviceOwnerAuthentication error:&aerr];
}

- (NSString*) getOrCreateKey:(nonnull NSData*) alias withOptions:(nonnull NSDictionary *)options
{
  SecKeyRef privateKeyRef = [self getPrivateKeyRef:alias withMessage:kAuthenticationRequired];
  if (privateKeyRef != nil) {
    return [self getPublicKeyBase64Encoded:alias];
  }

  CFErrorRef error = nil;
  CFStringRef keyAccessLevel = kSecAttrAccessibleAfterFirstUnlock;
  SecAccessControlCreateFlags acFlag = kSecAccessControlPrivateKeyUsage;
  int accessLevel = [options[kAccessLevel] intValue];
  BOOL invalidateOnNewBiometry = options[kInvalidateOnNewBiometry] && [options[kInvalidateOnNewBiometry] boolValue];
  
  switch(accessLevel) {
    case UNLOCKED_DEVICE:
      if (![self hasPassCode]) {
        [NSException raise:@"E1771" format:@"The device cannot meet requirements. No passcode has been set."];
      }
      keyAccessLevel = kSecAttrAccessibleWhenUnlockedThisDeviceOnly;
      acFlag = kSecAccessControlPrivateKeyUsage;
      break;
    case AUTHENTICATION_REQUIRED:
      if (![self hasBiometry]) {
        [NSException raise:@"E1771" format:@"The device cannot meet requirements. No biometry has been enrolled."];
      }
      keyAccessLevel = kSecAttrAccessibleWhenUnlockedThisDeviceOnly;
      if (@available(iOS 11.3, *)) {
          acFlag = invalidateOnNewBiometry ? kSecAccessControlBiometryCurrentSet | kSecAccessControlPrivateKeyUsage : kSecAccessControlBiometryAny | kSecAccessControlPrivateKeyUsage;
      } else {
        acFlag = kSecAccessControlPrivateKeyUsage;
      }
      break;
    default: // ALWAYS
      keyAccessLevel = kSecAttrAccessibleAfterFirstUnlock;
      acFlag = kSecAccessControlPrivateKeyUsage;
  }
  
  SecAccessControlRef acRef = SecAccessControlCreateWithFlags(kCFAllocatorDefault, keyAccessLevel, acFlag, &error);
  
  if (!acRef) {
    [NSException raise:@"E1711" format:@"Could not create access control."];
  }
  
  NSDictionary* attributes =
  @{ (id)kSecAttrKeyType:        (id)kSecAttrKeyTypeECSECPrimeRandom,
     (id)kSecAttrTokenID:        (id)kSecAttrTokenIDSecureEnclave,
     (id)kSecAttrKeySizeInBits:  @256,
     (id)kSecPrivateKeyAttrs:
       @{
         (id)kSecAttrLabel:          @"privateKey",
         (id)kSecAttrApplicationTag: alias,
         (id)kSecAttrIsPermanent:    (id)kCFBooleanTrue,
         (id)kSecAttrAccessControl:  (__bridge id)acRef
       },
         (id)kSecPublicKeyAttrs:
            @{
              (id)kSecAttrIsPermanent:    (id)kCFBooleanFalse,
            },
  };
  
  privateKeyRef = SecKeyCreateRandomKey((__bridge CFDictionaryRef)attributes, &error);
  if (!privateKeyRef){
    [NSException raise:@"E1712" format:@"SecKeyCreate could not create key."];
  }
  SecKeyRef publicKeyRef = SecKeyCopyPublicKey(privateKeyRef);
  [self savePublicKeyFromRef:publicKeyRef withAlias:alias];

  //using base64 encoding for public key rather than PEM as we also use this in react native
  return [self getPublicKeyBase64Encoded:alias];
}

// React-Native methods
#if TARGET_OS_IOS




RCT_EXPORT_METHOD(createKey:(nonnull NSData *)alias withOptions:(nonnull NSDictionary *)options resolver:(RCTPromiseResolveBlock)resolve rejecter:(RCTPromiseRejectBlock)reject)
{
  @try {
    NSString *keyType = options[kKeyType];
    NSString* publicKey = [self getOrCreateKey:alias withOptions:options];
    
    if (keyType.intValue == ASYMMETRIC) {
      resolve(publicKey);
    } else {
      resolve(publicKey != nil ? @(YES) : @(NO));
    }
  } @catch(NSException *err) {
    reject(err.name, err.reason, nil);
  }
}

RCT_EXPORT_METHOD(deleteKey:(nonnull NSData *)alias resolver:(RCTPromiseResolveBlock)resolve rejecter:(RCTPromiseRejectBlock)reject)
{
  [self deletePublicKey:alias];
  [self deletePrivateKey:alias];
  
  return resolve(@(YES));
}

// Method to warm up and store the private key reference
RCT_EXPORT_METHOD(authenticate:(NSString *)alias options:(NSDictionary *)options resolver:(RCTPromiseResolveBlock)resolve rejecter:(RCTPromiseRejectBlock)reject) {
    if (!self.authenticationContext) {
        self.authenticationContext = [[LAContext alloc] init];
        self.authenticationContext.touchIDAuthenticationAllowableReuseDuration = 30.0; // Adjust time as needed
    }
    
    NSString *authMessage = options[@"promptMessage"] ?: @"Authenticate to use private key";
    self.authenticationContext.localizedFallbackTitle = ""; // Optional: customize or leave empty

    [self.authenticationContext evaluatePolicy:LAPolicyDeviceOwnerAuthenticationWithBiometrics localizedReason:authMessage reply:^(BOOL success, NSError *error) {
        if (success) {
            NSData *aliasData = [alias dataUsingEncoding:NSUTF8StringEncoding];
            NSDictionary *query = @{
                (id)kSecClass: (id)kSecClassKey,
                (id)kSecAttrKeyClass: (id)kSecAttrKeyClassPrivate,
                (id)kSecAttrLabel: @"privateKey",
                (id)kSecAttrApplicationTag: aliasData,
                (id)kSecReturnRef: @YES,
                (id)kSecUseAuthenticationContext: self.authenticationContext
            };
            SecKeyRef privateKeyRef = NULL;
            OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)query, (CFTypeRef *)&privateKeyRef);
            if (status == errSecSuccess) {
                self.privateKeyRef = privateKeyRef;
                resolve(@(YES));
            } else {
                reject(@"E1701", @"Could not retrieve private key", error);
            }
        } else {
            reject(@"AuthenticationError", error.localizedDescription, error);
        }
    }];
}


// Method to clean up and release the private key reference
RCT_EXPORT_METHOD(cleanUp:(RCTPromiseResolveBlock)resolve rejecter:(RCTPromiseRejectBlock)reject) {
    if (self.privateKeyRef) {
        CFRelease(self.privateKeyRef); // Release the SecKeyRef
        self.privateKeyRef = nil;      // Nullify the pointer to prevent dangling references
    }
    self.authenticationContext = nil; // Release the context to ensure it doesn't stay authenticated longer than needed
    resolve(@(YES));
}



// Updated sign method using the stored private key reference
RCT_EXPORT_METHOD(sign:(NSString *)alias withPlainText:(NSString *)plainText withOptions:(NSDictionary *)options resolver:(RCTPromiseResolveBlock)resolve rejecter:(RCTPromiseRejectBlock)reject) {
    @try {
        if (!self.privateKeyRef) {
            [NSException raise:@"PrivateKeyError" format:@"Private key reference not initialized."];
        }
        NSData *textToBeSigned = [[NSData alloc] initWithBase64EncodedString:plainText options:0];
        if (!textToBeSigned) {
            [NSException raise:@"InvalidInput" format:@"Input string is not a valid base64."];
        }

        CFErrorRef aerr = NULL;
        NSData *signatureBytes = (NSData*)CFBridgingRelease(SecKeyCreateSignature(self.privateKeyRef, kSecKeyAlgorithmECDSASignatureMessageX962SHA256, (__bridge CFDataRef)textToBeSigned, &aerr));
        
        if (aerr) {
            NSError *err = CFBridgingRelease(aerr);
            reject(@"SignatureError", @"Error creating signature", err);
            return;
        }

        resolve([signatureBytes base64EncodedStringWithOptions:0]);
    } @catch(NSException *exception) {
        reject(exception.name, exception.reason, nil);
    }
}


RCT_EXPORT_METHOD(encrypt:(nonnull NSString *)publicKeyBase64 withPlainText:(nonnull NSString *)plainText withOptions:(nonnull NSDictionary *)options resolver:(RCTPromiseResolveBlock)resolve rejecter:(RCTPromiseRejectBlock)reject)
{
  @try {
      CFErrorRef aerr = NULL;
      NSData* cipherText = nil;
      // NSData *textToBeEncrypted = [plainText dataUsingEncoding:NSUTF8StringEncoding];
      NSData *textToBeEncrypted = [[NSData alloc] initWithBase64EncodedString:plainText options:0];
      if (!textToBeEncrypted) {
          [NSException raise:@"E1718 - Invalid input." format:@"Input string is not a valid base64."];
      }
      
      // Decode the base64-encoded public key
      NSData *publicKeyData = [[NSData alloc] initWithBase64EncodedString:publicKeyBase64 options:0];
      NSDictionary *publicKeyAttributes = @{
          (id)kSecAttrKeyType: (id)kSecAttrKeyTypeECSECPrimeRandom,
          (id)kSecAttrKeyClass: (id)kSecAttrKeyClassPublic,
          (id)kSecAttrKeySizeInBits: @256,
      };
      SecKeyRef publicKey = SecKeyCreateWithData((__bridge CFDataRef)publicKeyData,
                                                  (__bridge CFDictionaryRef)publicKeyAttributes,
                                                  &aerr);
      if (!publicKey || aerr) {
          [NSException raise:@"E1761 - Public Key Error" format:@"%@", aerr];
      }
      
      // Check if the public key supports encryption
      BOOL canEncrypt = SecKeyIsAlgorithmSupported(publicKey, kSecKeyOperationTypeEncrypt, kSecKeyAlgorithmECIESEncryptionCofactorVariableIVX963SHA256AESGCM);
      if (!canEncrypt) {
          [NSException raise:@"E1759 - Device cannot encrypt." format:@"%@", nil];
      }
      
      // Encrypt the data
      cipherText = (NSData*)CFBridgingRelease(
                                              SecKeyCreateEncryptedData(publicKey,
                                                                        kSecKeyAlgorithmECIESEncryptionCofactorVariableIVX963SHA256AESGCM,
                                                                        (__bridge CFDataRef)textToBeEncrypted,
                                                                        &aerr));
      if (!cipherText || aerr) {
          [NSException raise:@"E1760 - Encryption error." format:@"%@", aerr];
      }
      
      if (publicKey) { CFRelease(publicKey); }
      if (aerr) { CFRelease(aerr); }
      
      // Resolve the promise with the encrypted text
      resolve(@{
        @"iv": @"NotRequired",
        @"encryptedText": [cipherText base64EncodedStringWithOptions:0],
      });
  } @catch(NSException *err) {
      reject(err.name, err.description, nil);
  }
}

// Assuming the `privateKeyRef` is a property of your module

RCT_EXPORT_METHOD(decrypt:(NSString *)alias withCipherText:(NSString *)cipherText withOptions:(NSDictionary *)options resolver:(RCTPromiseResolveBlock)resolve rejecter:(RCTPromiseRejectBlock)reject) {
    @try {
        if (!self.privateKeyRef) {
            NSString *authMessage = options[@"promptMessage"] ?: @"Authenticate to use private key";
            NSData *aliasData = [alias dataUsingEncoding:NSUTF8StringEncoding];
            NSDictionary *query = @{
                (id)kSecClass: (id)kSecClassKey,
                (id)kSecAttrKeyClass: (id)kSecAttrKeyClassPrivate,
                (id)kSecAttrLabel: @"privateKey",
                (id)kSecAttrApplicationTag: aliasData,
                (id)kSecReturnRef: @YES,
                (id)kSecUseAuthenticationContext: self.authenticationContext
            };
            SecKeyRef privateKeyRef = NULL;
            OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)query, (CFTypeRef *)&privateKeyRef);
            if (status != errSecSuccess) {
                [NSException raise:@"PrivateKeyError" format:@"Private key reference not available or not authenticated."];
            }
            self.privateKeyRef = privateKeyRef;
        }
        NSData *dataToBeDecrypted = [[NSData alloc] initWithBase64EncodedString:cipherText options:0];
        if (!dataToBeDecrypted) {
            [NSException raise:@"InvalidInput" format:@"Cipher text is not valid base64."];
        }

        CFErrorRef aerr = NULL;
        NSData *clearTextData = (NSData*)CFBridgingRelease(SecKeyCreateDecryptedData(self.privateKeyRef, kSecKeyAlgorithmECIESEncryptionCofactorVariableIVX963SHA256AESGCM, (__bridge CFDataRef)dataToBeDecrypted, &aerr));

        if (!clearTextData || aerr) {
            NSError *err = CFBridgingRelease(aerr);
            reject(@"DecryptionError", @"Failed to decrypt data", err);
            return;
        }

        NSString *resultString = [clearTextData base64EncodedStringWithOptions:0];
        resolve(resultString);
    } @catch(NSException *exception) {
        reject(exception.name, exception.reason, nil);
    }
}


// HELPERS
// ______________________________________________
RCT_EXPORT_METHOD(getPublicKey:(nonnull NSData *)alias resolver:(RCTPromiseResolveBlock)resolve rejecter:(RCTPromiseRejectBlock)reject)
{
  return resolve([self getPublicKeyBase64Encoded:alias]);
}

RCT_EXPORT_METHOD(isKeyExists:(nonnull NSData *)alias withKeyType:(nonnull NSNumber *) keyType resolver:(RCTPromiseResolveBlock)resolve rejecter:(RCTPromiseRejectBlock)reject)
{
  @try {
    SecKeyRef privateKeyRef = [self getPrivateKeyRef:alias withMessage:nil];
    resolve((privateKeyRef == nil) ? @(NO) : @(YES));
  } @catch(NSException *err) {
    reject(err.name, err.description, nil);
  }
}

RCT_EXPORT_METHOD(isBiometryEnrolled:(RCTPromiseResolveBlock)resolve rejecter:(RCTPromiseRejectBlock)reject)
{
  @try {
    resolve([self hasBiometry] ? @(YES) : @(NO));
  } @catch(NSException *err) {
    reject(err.name, err.reason, nil);
  }
}

RCT_EXPORT_METHOD(deviceSecurityLevel:(RCTPromiseResolveBlock)resolve rejecter:(RCTPromiseRejectBlock)reject)
{
  @try {
    if ([self hasBiometry]) {
      resolve(@"BIOMETRY");
      return;
    }
    if ([self hasPassCode]) {
      resolve(@"PIN_OR_PATTERN");
      return;
    }
    
    resolve(@"NOT_PROTECTED");
  } @catch(NSException *err) {
    reject(err.name, err.reason, nil);
  }
}

RCT_EXPORT_METHOD(getBiometryType:(RCTPromiseResolveBlock)resolve rejecter:(RCTPromiseRejectBlock)reject)
{
  @try {
    NSError *aerr = nil;
    LAContext *context = [[LAContext alloc] init];
    BOOL canBeProtected = [context canEvaluatePolicy:LAPolicyDeviceOwnerAuthenticationWithBiometrics error:&aerr];
    
    if (aerr || !canBeProtected) {
      [NSException raise:@"Couldn't get biometry type" format:@"%@", aerr];
    }
    
    if (@available(iOS 11, *)) {
      if (context.biometryType == LABiometryTypeFaceID) {
        resolve(@"FACE");
        return;
      }
      else if (context.biometryType == LABiometryTypeTouchID) {
        resolve(@"TOUCH");
        return;
      }
      else if (context.biometryType == LABiometryNone) {
        resolve(@"NONE");
        return;
      } else {
        resolve(@"TOUCH");
        return;
      }
    }
    
    resolve(@"TOUCH");
  } @catch (NSException *err) {
    reject(err.name, err.description, nil);
  }
}

RCT_EXPORT_METHOD(authenticateWithBiometry:(nonnull NSDictionary *)options resolver:(RCTPromiseResolveBlock)resolve rejecter:(RCTPromiseRejectBlock)reject)
{
  dispatch_async(dispatch_get_global_queue( DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
    NSString *authMessage = kAuthenticationRequired;
    if (options && options[kAuthenticatePrompt]){
      authMessage = options[kAuthenticatePrompt];
    }
    
    LAContext *context = [[LAContext alloc] init];
    context.localizedFallbackTitle = @"";
    [context evaluatePolicy:LAPolicyDeviceOwnerAuthenticationWithBiometrics localizedReason:authMessage reply:^(BOOL success, NSError *aerr) {
      if (success) {
        resolve(@(YES));
      } else if (aerr.code == LAErrorUserCancel) {
        resolve(@(NO));
      } else {
        reject(@"Biometry error", aerr.localizedDescription, nil);
      }
    }];
  });
}

#endif


@end
