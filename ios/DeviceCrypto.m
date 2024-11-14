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
// - (SecKeyRef)retrievePrivateKeyRef:(nonnull NSData *)alias withMessage:(NSString *)authMessage error:(NSError **)error {
//     @try {
//         return [self getPrivateKeyRef:alias withMessage:authMessage];
//     } @catch (NSException *exception) {
//         if (error) {
//             *error = [NSError errorWithDomain:@"PrivateKeyRetrievalError"
//                                          code:1001
//                                      userInfo:@{NSLocalizedDescriptionKey: exception.description}];
//         }
//         return nil;
//     }
// }

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
    dispatch_async(dispatch_get_global_queue( DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{

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
      });

}

RCT_EXPORT_METHOD(deleteKey:(nonnull NSData *)alias resolver:(RCTPromiseResolveBlock)resolve rejecter:(RCTPromiseRejectBlock)reject)
{
  [self deletePublicKey:alias];
  [self deletePrivateKey:alias];
  
  return resolve(@(YES));
}

// Method to perform biometric authentication and set up LAContext
RCT_EXPORT_METHOD(authenticate:(NSDictionary *)options resolver:(RCTPromiseResolveBlock)resolve rejecter:(RCTPromiseRejectBlock)reject) {
    // Retrieve custom prompt message or use default
    NSString *authPrompt = options[@"promptMessage"] ?: @"Authenticate to proceed";

    [self ensureAuthenticationWithPrompt:authPrompt completion:^(BOOL success, NSError *error) {
        // Ensure callbacks are called on the main thread
        dispatch_async(dispatch_get_main_queue(), ^{
            if (success) {
                resolve(@(YES));
            } else {
                reject(@"AuthenticationError", error.localizedDescription, error);
            }
        });
    }];
}



// Method to clean up and release the LAContext
RCT_EXPORT_METHOD(cleanUp:(RCTPromiseResolveBlock)resolve rejecter:(RCTPromiseRejectBlock)reject) {
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        @try {
            if (self.authenticationContext) {
                self.authenticationContext = nil; // Release the context
            }
            resolve(@(YES));
        } @catch (NSException *exception) {
            reject(exception.name, exception.reason, nil);
        }
    });
}



// Updated sign method with graceful authentication handling
RCT_EXPORT_METHOD(sign:(NSString *)alias withPlainText:(NSString *)plainText withOptions:(NSDictionary *)options resolver:(RCTPromiseResolveBlock)resolve rejecter:(RCTPromiseRejectBlock)reject) {
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        @try {
            // Check if authentication context is set; if not, authenticate
            if (!self.authenticationContext) {
                NSString *authPrompt = options[@"promptMessage"] ?: @"Authenticate to sign data";
                dispatch_semaphore_t sema = dispatch_semaphore_create(0);
                __block BOOL authSuccess = NO;
                __block NSError *authError = nil;

                [self ensureAuthenticationWithPrompt:authPrompt completion:^(BOOL success, NSError *error) {
                    authSuccess = success;
                    authError = error;
                    dispatch_semaphore_signal(sema);
                }];

                // Wait for authentication to complete
                dispatch_semaphore_wait(sema, DISPATCH_TIME_FOREVER);

                if (!authSuccess) {
                    reject(@"AuthenticationError", authError.localizedDescription, authError);
                    return;
                }
            }

            NSData *aliasData = [alias dataUsingEncoding:NSUTF8StringEncoding];
            NSMutableDictionary *query = [@{
                (id)kSecClass: (id)kSecClassKey,
                (id)kSecAttrKeyClass: (id)kSecAttrKeyClassPrivate,
                (id)kSecAttrApplicationTag: aliasData,
                (id)kSecReturnRef: @YES,
                (id)kSecUseAuthenticationContext: self.authenticationContext,
                (id)kSecUseAuthenticationUI: (id)kSecUseAuthenticationUISkip // Skip UI if possible
            } mutableCopy];

            SecKeyRef privateKeyRef = NULL;
            OSStatus status = SecItemCopyMatching((__bridge CFDictionaryRef)query, (CFTypeRef *)&privateKeyRef);
            NSLog(@"SecItemCopyMatching status: %d", status);

            if (status == errSecInteractionNotAllowed) {
                // Authentication session may have expired, retry authentication
                self.authenticationContext = nil; // Reset the context
                NSString *authPrompt = options[@"promptMessage"] ?: @"Authenticate to sign data";
                dispatch_semaphore_t sema = dispatch_semaphore_create(0);
                __block BOOL authSuccess = NO;
                __block NSError *authError = nil;

                [self ensureAuthenticationWithPrompt:authPrompt completion:^(BOOL success, NSError *error) {
                    authSuccess = success;
                    authError = error;
                    dispatch_semaphore_signal(sema);
                }];

                // Wait for authentication to complete
                dispatch_semaphore_wait(sema, DISPATCH_TIME_FOREVER);

                if (!authSuccess) {
                    reject(@"AuthenticationError", authError.localizedDescription, authError);
                    return;
                }

                // Retry retrieving the private key with new authentication context
                query = [query mutableCopy];
                query[(id)kSecUseAuthenticationContext] = self.authenticationContext;
                status = SecItemCopyMatching((__bridge CFDictionaryRef)query, (CFTypeRef *)&privateKeyRef);

                NSLog(@"SecItemCopyMatching retry status: %d", status);
            }

            if (status != errSecSuccess || !privateKeyRef) {
                NSError *error = [NSError errorWithDomain:NSOSStatusErrorDomain code:status userInfo:nil];
                reject(@"PrivateKeyError", @"Private key not found or authentication failed.", error);
                return;
            }

            // Decode the plain text from base64
            NSData *textToBeSigned = [[NSData alloc] initWithBase64EncodedString:plainText options:0];
            if (!textToBeSigned) {
                CFRelease(privateKeyRef);
                [NSException raise:@"InvalidInput" format:@"Input string is not a valid base64."];
            }

            // Create the signature
            CFErrorRef aerr = NULL;
            SecKeyAlgorithm algorithm = kSecKeyAlgorithmECDSASignatureMessageX962SHA256;
            if (!SecKeyIsAlgorithmSupported(privateKeyRef, kSecKeyOperationTypeSign, algorithm)) {
                CFRelease(privateKeyRef);
                [NSException raise:@"AlgorithmError" format:@"The algorithm is not supported for signing."];
            }

            CFDataRef signature = SecKeyCreateSignature(privateKeyRef, algorithm, (__bridge CFDataRef)textToBeSigned, &aerr);
            CFRelease(privateKeyRef); // Release the key reference

            if (aerr) {
                NSError *err = CFBridgingRelease(aerr);
                reject(@"SignatureError", @"Error creating signature", err);
                return;
            }

            NSData *signatureData = (__bridge_transfer NSData *)signature;
            NSString *signatureBase64 = [signatureData base64EncodedStringWithOptions:0];
            resolve(signatureBase64);
        } @catch (NSException *exception) {
            reject(exception.name, exception.reason, nil);
        }
    });
}


//from react-native-keychain with LAContext
// Method to set internet credentials for a server with LAContext
// Updated setInternetCredentialsForServer method with graceful authentication handling
RCT_EXPORT_METHOD(setInternetCredentialsForServer:(NSString *)server
                      withUsername:(NSString *)username
                      withPassword:(NSString *)password
                      withOptions:(NSDictionary *)options
                      resolver:(RCTPromiseResolveBlock)resolve
                      rejecter:(RCTPromiseRejectBlock)reject)
{
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        @try {
            CFBooleanRef cloudSync = cloudSyncValue(options);
            NSString *authenticationPrompt = options[@"promptMessage"] ?: @"Authenticate to save credentials";

            // Check if authentication context is set; if not, authenticate
            if (!self.authenticationContext) {
                dispatch_semaphore_t sema = dispatch_semaphore_create(0);
                __block BOOL authSuccess = NO;
                __block NSError *authError = nil;

                [self ensureAuthenticationWithPrompt:authenticationPrompt completion:^(BOOL success, NSError *error) {
                    authSuccess = success;
                    authError = error;
                    dispatch_semaphore_signal(sema);
                }];

                // Wait for authentication to complete
                dispatch_semaphore_wait(sema, DISPATCH_TIME_FOREVER);

                if (!authSuccess) {
                    reject(@"AuthenticationError", authError.localizedDescription, authError);
                    return;
                }
            }

            // Delete existing credentials
            [self deleteCredentialsForServer:server withOptions:options];

            // Create access control
            CFErrorRef error = NULL;
            SecAccessControlRef accessControl = SecAccessControlCreateWithFlags(
                kCFAllocatorDefault,
                kSecAttrAccessibleWhenUnlocked,
                kSecAccessControlUserPresence, // Requires user presence (biometric or passcode)
                &error
            );
            if (error) {
                NSError *err = CFBridgingRelease(error);
                reject(@"AccessControlError", @"Failed to create access control", err);
                return;
            }

            NSMutableDictionary *attributes = [@{
                (__bridge NSString *)kSecClass: (__bridge id)(kSecClassInternetPassword),
                (__bridge NSString *)kSecAttrServer: server,
                (__bridge NSString *)kSecAttrAccount: username,
                (__bridge NSString *)kSecValueData: [password dataUsingEncoding:NSUTF8StringEncoding],
                (__bridge NSString *)kSecAttrSynchronizable: (__bridge id)(cloudSync),
                (__bridge NSString *)kSecAttrAccessControl: (__bridge id)accessControl,
                (__bridge NSString *)kSecUseAuthenticationContext: self.authenticationContext,
                (__bridge NSString *)kSecUseAuthenticationUI: (__bridge NSString *)kSecUseAuthenticationUISkip // Skip UI if possible
            } mutableCopy];

            OSStatus osStatus = SecItemAdd((__bridge CFDictionaryRef)attributes, NULL);

            if (osStatus == errSecInteractionNotAllowed) {
                // Authentication session may have expired, re-authenticate
                self.authenticationContext = nil;
                dispatch_semaphore_t sema = dispatch_semaphore_create(0);
                __block BOOL authSuccess = NO;
                __block NSError *authError = nil;

                [self ensureAuthenticationWithPrompt:authenticationPrompt completion:^(BOOL success, NSError *error) {
                    authSuccess = success;
                    authError = error;
                    dispatch_semaphore_signal(sema);
                }];

                // Wait for authentication to complete
                dispatch_semaphore_wait(sema, DISPATCH_TIME_FOREVER);

                if (!authSuccess) {
                    if (accessControl) {
                        CFRelease(accessControl);
                    }
                    reject(@"AuthenticationError", authError.localizedDescription, authError);
                    return;
                }

                // Retry adding the item with new authentication context
                attributes = [attributes mutableCopy];
                attributes[(__bridge NSString *)kSecUseAuthenticationContext] = self.authenticationContext;
                osStatus = SecItemAdd((__bridge CFDictionaryRef)attributes, NULL);

            }

            if (accessControl) {
                CFRelease(accessControl);
            }

            if (osStatus == errSecDuplicateItem) {
                // Item already exists, update it
                NSDictionary *query = @{
                    (__bridge NSString *)kSecClass: (__bridge id)(kSecClassInternetPassword),
                    (__bridge NSString *)kSecAttrServer: server,
                    (__bridge NSString *)kSecAttrSynchronizable: (__bridge id)(cloudSync),
                };
                NSDictionary *updateAttributes = @{
                    (__bridge NSString *)kSecValueData: [password dataUsingEncoding:NSUTF8StringEncoding],
                    (__bridge NSString *)kSecAttrAccessControl: (__bridge id)accessControl,
                    (__bridge NSString *)kSecUseAuthenticationContext: self.authenticationContext,
                    (__bridge NSString *)kSecUseAuthenticationUI: (__bridge NSString *)kSecUseAuthenticationUISkip
                };
                osStatus = SecItemUpdate((__bridge CFDictionaryRef)query, (__bridge CFDictionaryRef)updateAttributes);
            }

            if (osStatus == errSecSuccess) {
                resolve(@(YES));
            } else if (osStatus == errSecInteractionNotAllowed) {
                reject(@"AuthenticationExpired", @"Authentication has expired. Please authenticate again.", nil);
            } else {
                NSError *error = [NSError errorWithDomain:NSOSStatusErrorDomain code:osStatus userInfo:nil];
                reject(@"KeychainError", @"Failed to set Keychain item", error);
            }

        } @catch (NSException *exception) {
            reject(exception.name, exception.reason, nil);
        }
    });
}


// Updated getInternetCredentialsForServer method with graceful authentication handling
RCT_EXPORT_METHOD(getInternetCredentialsForServer:(NSString *)server
                      withOptions:(NSDictionary * __nullable)options
                      resolver:(RCTPromiseResolveBlock)resolve
                      rejecter:(RCTPromiseRejectBlock)reject)
{
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        @try {
            CFBooleanRef cloudSync = cloudSyncValue(options);
            NSString *authenticationPrompt = authenticationPromptValue(options) ?: @"Authenticate to retrieve credentials";

            // Check if authentication context is set; if not, authenticate
            if (!self.authenticationContext) {
                dispatch_semaphore_t sema = dispatch_semaphore_create(0);
                __block BOOL authSuccess = NO;
                __block NSError *authError = nil;

                [self ensureAuthenticationWithPrompt:authenticationPrompt completion:^(BOOL success, NSError *error) {
                    authSuccess = success;
                    authError = error;
                    dispatch_semaphore_signal(sema);
                }];

                // Wait for authentication to complete
                dispatch_semaphore_wait(sema, DISPATCH_TIME_FOREVER);

                if (!authSuccess) {
                    reject(@"AuthenticationError", authError.localizedDescription, authError);
                    return;
                }
            }

            NSMutableDictionary *query = [@{
                (__bridge NSString *)kSecClass: (__bridge id)(kSecClassInternetPassword),
                (__bridge NSString *)kSecAttrServer: server,
                (__bridge NSString *)kSecReturnAttributes: (__bridge id)kCFBooleanTrue,
                (__bridge NSString *)kSecAttrSynchronizable: (__bridge id)(cloudSync),
                (__bridge NSString *)kSecReturnData: (__bridge id)kCFBooleanTrue,
                (__bridge NSString *)kSecMatchLimit: (__bridge NSString *)kSecMatchLimitOne,
                (__bridge NSString *)kSecUseAuthenticationContext: self.authenticationContext,
                (__bridge NSString *)kSecUseOperationPrompt: authenticationPrompt,
                (__bridge NSString *)kSecUseAuthenticationUI: (__bridge NSString *)kSecUseAuthenticationUISkip // Skip UI if possible
            } mutableCopy];


            // Look up server in the keychain
            CFTypeRef foundTypeRef = NULL;
            OSStatus osStatus = SecItemCopyMatching((__bridge CFDictionaryRef)query, &foundTypeRef);

            if (osStatus == errSecInteractionNotAllowed) {
                // Authentication session may have expired, re-authenticate
                self.authenticationContext = nil;
                dispatch_semaphore_t sema = dispatch_semaphore_create(0);
                __block BOOL authSuccess = NO;
                __block NSError *authError = nil;

                [self ensureAuthenticationWithPrompt:authenticationPrompt completion:^(BOOL success, NSError *error) {
                    authSuccess = success;
                    authError = error;
                    dispatch_semaphore_signal(sema);
                }];

                // Wait for authentication to complete
                dispatch_semaphore_wait(sema, DISPATCH_TIME_FOREVER);

                if (!authSuccess) {
                    reject(@"AuthenticationError", authError.localizedDescription, authError);
                    return;
                }

                // Retry retrieving the item with new authentication context
                query = [query mutableCopy];
                query[(__bridge NSString *)kSecUseAuthenticationContext] = self.authenticationContext;
                osStatus = SecItemCopyMatching((__bridge CFDictionaryRef)query, &foundTypeRef);

            }

            if (osStatus == errSecItemNotFound) {
                resolve(@(NO));
                return;
            } else if (osStatus != errSecSuccess) {
                NSError *error = [NSError errorWithDomain:NSOSStatusErrorDomain code:osStatus userInfo:nil];
                reject(@"KeychainError", @"Failed to retrieve Keychain item", error);
                return;
            }

            NSDictionary *found = (__bridge_transfer NSDictionary *)foundTypeRef;
            if (!found) {
                resolve(@(NO));
                return;
            }

            // Extract credentials
            NSString *username = (NSString *)[found objectForKey:(__bridge id)(kSecAttrAccount)];
            NSData *passwordData = [found objectForKey:(__bridge id)(kSecValueData)];
            NSString *password = [[NSString alloc] initWithData:passwordData encoding:NSUTF8StringEncoding];

            resolve(@{
                @"server": server,
                @"username": username,
                @"password": password,
                @"storage": @"keychain"
            });

        } @catch (NSException *exception) {
            reject(exception.name, exception.reason, nil);
        }
    });
}

// Updated resetInternetCredentialsForOptions method with graceful authentication handling
RCT_EXPORT_METHOD(resetInternetCredentialsForOptions:(NSDictionary *)options
                      resolver:(RCTPromiseResolveBlock)resolve
                      rejecter:(RCTPromiseRejectBlock)reject)
{
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        @try {
            NSString *server = serverValue(options);
            NSString *authenticationPrompt = options[@"promptMessage"] ?: @"Authenticate to reset credentials";

            // Check if authentication context is set; if not, authenticate
            if (!self.authenticationContext) {
                dispatch_semaphore_t sema = dispatch_semaphore_create(0);
                __block BOOL authSuccess = NO;
                __block NSError *authError = nil;

                [self ensureAuthenticationWithPrompt:authenticationPrompt completion:^(BOOL success, NSError *error) {
                    authSuccess = success;
                    authError = error;
                    dispatch_semaphore_signal(sema);
                }];

                // Wait for authentication to complete
                dispatch_semaphore_wait(sema, DISPATCH_TIME_FOREVER);

                if (!authSuccess) {
                    reject(@"AuthenticationError", authError.localizedDescription, authError);
                    return;
                }
            }

            OSStatus osStatus = [self deleteCredentialsForServer:server withOptions:options];
            if (osStatus == errSecInteractionNotAllowed) {
                // Authentication session may have expired, re-authenticate
                self.authenticationContext = nil;
                dispatch_semaphore_t sema = dispatch_semaphore_create(0);
                __block BOOL authSuccess = NO;
                __block NSError *authError = nil;

                [self ensureAuthenticationWithPrompt:authenticationPrompt completion:^(BOOL success, NSError *error) {
                    authSuccess = success;
                    authError = error;
                    dispatch_semaphore_signal(sema);
                }];

                // Wait for authentication to complete
                dispatch_semaphore_wait(sema, DISPATCH_TIME_FOREVER);

                if (!authSuccess) {
                    reject(@"AuthenticationError", authError.localizedDescription, authError);
                    return;
                }

                // Retry deletion with new authentication context
                osStatus = [self deleteCredentialsForServer:server withOptions:options];
            }

            if (osStatus != errSecSuccess && osStatus != errSecItemNotFound) {
                NSError *error = [NSError errorWithDomain:NSOSStatusErrorDomain code:osStatus userInfo:nil];
                reject(@"KeychainError", @"Failed to reset Keychain item", error);
                return;
            }

            resolve(@(YES));
        } @catch (NSException *exception) {
            reject(exception.name, exception.reason, nil);
        }
    });
}





// HELPERS
// ______________________________________________
RCT_EXPORT_METHOD(getPublicKey:(nonnull NSData *)alias resolver:(RCTPromiseResolveBlock)resolve rejecter:(RCTPromiseRejectBlock)reject)
{
  return resolve([self getPublicKeyBase64Encoded:alias]);
}

// Helper method to ensure authentication is in place
- (void)ensureAuthenticationWithPrompt:(NSString *)prompt completion:(void (^)(BOOL success, NSError *error))completion {
    // Initialize LAContext
    self.authenticationContext = [[LAContext alloc] init];
    self.authenticationContext.touchIDAuthenticationAllowableReuseDuration = 30.0; // Adjust as needed
    self.authenticationContext.localizedFallbackTitle = @""; // Optional: customize or leave empty

    NSLog(@"Starting biometric authentication");

    // Perform biometric authentication
    [self.authenticationContext evaluatePolicy:LAPolicyDeviceOwnerAuthenticationWithBiometrics
                               localizedReason:prompt
                                         reply:^(BOOL success, NSError *error) {
        if (completion) {
            completion(success, error);
        }
    }];
}

// Adjusted deleteCredentialsForServer method
- (OSStatus)deleteCredentialsForServer:(NSString *)server withOptions:(NSDictionary *)options {
    CFBooleanRef cloudSync = cloudSyncValue(options);

    NSMutableDictionary *query = [@{
        (__bridge NSString *)kSecClass: (__bridge id)kSecClassInternetPassword,
        (__bridge NSString *)kSecAttrServer: server,
        (__bridge NSString *)kSecAttrSynchronizable: (__bridge id)(cloudSync),
        (__bridge NSString *)kSecUseAuthenticationContext: self.authenticationContext,
        (__bridge NSString *)kSecUseAuthenticationUI: (__bridge NSString *)kSecUseAuthenticationUISkip
    } mutableCopy];

    OSStatus osStatus = SecItemDelete((__bridge CFDictionaryRef)query);
    return osStatus;
}

// Helper function to retrieve cloud synchronization option
CFBooleanRef cloudSyncValue(NSDictionary *options) {
    NSNumber *synchronizableOption = options[@"synchronizable"];
    if (synchronizableOption && [synchronizableOption boolValue]) {
        return kCFBooleanTrue;
    } else {
        return kCFBooleanFalse;
    }
}

// Helper function to retrieve authentication prompt message
NSString *authenticationPromptValue(NSDictionary *options) {
    NSString *prompt = options[@"promptMessage"];
    if (prompt) {
        return prompt;
    } else {
        return @"Authenticate to proceed";
    }
}

// Helper function to retrieve server value from options
NSString *serverValue(NSDictionary *options) {
    NSString *server = options[@"server"];
    if (server) {
        return server;
    } else {
        // Handle the case where server is not provided
        return @"";
    }
}

// Helper function to reject a promise with an NSError
void rejectWithError(RCTPromiseRejectBlock reject, NSError *error) {
    if (reject) {
        reject([NSString stringWithFormat:@"%ld", (long)error.code], error.localizedDescription, error);
    }
}




#endif


@end
