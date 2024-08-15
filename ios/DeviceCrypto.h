#import <React/RCTBridgeModule.h>
#import <React/RCTLog.h>

@interface DeviceCrypto : NSObject <RCTBridgeModule>
@property (nonatomic, assign) SecKeyRef privateKeyRef;
@property (nonatomic, strong) LAContext *authenticationContext;

@end
