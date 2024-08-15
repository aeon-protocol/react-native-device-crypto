#import <React/RCTBridgeModule.h>
#import <React/RCTLog.h>

@interface DeviceCrypto : NSObject <RCTBridgeModule>
@property (nonatomic, assign) SecKeyRef privateKeyRef;

@end
