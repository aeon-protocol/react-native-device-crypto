#import <React/RCTBridgeModule.h>
#import <React/RCTLog.h>
#import <LocalAuthentication/LocalAuthentication.h>
#import <Security/Security.h>

@interface DeviceCrypto : NSObject <RCTBridgeModule>
@property (nonatomic, strong) LAContext *authenticationContext;

@end
