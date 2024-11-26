#import <AuthenticationServices/AuthenticationServices.h>
#import <Cordova/CDVPlugin.h> // this already includes Foundation.h

@interface SignInWithApple : CDVPlugin <ASAuthorizationControllerDelegate>
@property (nonatomic, strong) NSString *callbackId;
@end

@implementation SignInWithApple

- (void)pluginInitialize {
    NSLog(@"[SignInWithApple] Plugin initialized");
}

- (NSArray<ASAuthorizationScope> *)convertScopes:(NSArray<NSNumber *> *)scopes {
    NSMutableArray<ASAuthorizationScope> *convertedScopes = [NSMutableArray array];

    for (NSNumber *scope in scopes) {
        switch (scope.integerValue) {
            case 0:
                [convertedScopes addObject:ASAuthorizationScopeFullName];
                break;
            case 1:
                [convertedScopes addObject:ASAuthorizationScopeEmail];
                break;
            default:
                NSLog(@"[SignInWithApple] Unknown scope: %@", scope);
                break;
        }
    }

    return [convertedScopes copy];
}

- (void)signin:(CDVInvokedUrlCommand *)command {
    if (@available(iOS 13.0, *)) {
        self.callbackId = command.callbackId;
        NSDictionary *options = command.arguments.firstObject;

        ASAuthorizationAppleIDProvider *provider = [[ASAuthorizationAppleIDProvider alloc] init];
        ASAuthorizationAppleIDRequest *request = [provider createRequest];

        if (options[@"requestedScopes"]) {
            request.requestedScopes = [self convertScopes:options[@"requestedScopes"]];
        }

        ASAuthorizationController *controller = [[ASAuthorizationController alloc] initWithAuthorizationRequests:@[request]];
        controller.delegate = self;
        [controller performRequests];
    } else {
        NSLog(@"[SignInWithApple] Sign in ignored for iOS version < 13");

        CDVPluginResult *result = [CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR
                                              messageAsDictionary:@{
                                                  @"error" : @"PLUGIN_ERROR",
                                                  @"code" : @"UNSUPPORTED_IOS_VERSION",
                                                  @"localizedDescription" : @"Sign in with Apple requires iOS 13 or higher."
                                              }];
        [self.commandDelegate sendPluginResult:result callbackId:command.callbackId];
    }
}

- (void)authorizationController:(ASAuthorizationController *)controller
    didCompleteWithAuthorization:(ASAuthorization *)authorization API_AVAILABLE(ios(13.0)) {
    ASAuthorizationAppleIDCredential *credential = authorization.credential;

    NSDictionary *fullName = [self parseFullName:credential.fullName];
    NSString *identityToken = [[NSString alloc] initWithData:credential.identityToken encoding:NSUTF8StringEncoding];
    NSString *authorizationCode = [[NSString alloc] initWithData:credential.authorizationCode encoding:NSUTF8StringEncoding];

    NSDictionary *response = @{
        @"user" : credential.user ?: @"",
        @"state" : credential.state ?: @"",
        @"fullName" : fullName ?: @{},
        @"email" : credential.email ?: @"",
        @"identityToken" : identityToken ?: @"",
        @"authorizationCode" : authorizationCode ?: @""
    };

    CDVPluginResult *result = [CDVPluginResult resultWithStatus:CDVCommandStatus_OK messageAsDictionary:response];
    [self.commandDelegate sendPluginResult:result callbackId:self.callbackId];
}

- (NSDictionary *)parseFullName:(NSPersonNameComponents *)nameComponents {
    if (!nameComponents) {
        return @{};
    }

    return @{
        @"namePrefix" : nameComponents.namePrefix ?: @"",
        @"givenName" : nameComponents.givenName ?: @"",
        @"middleName" : nameComponents.middleName ?: @"",
        @"familyName" : nameComponents.familyName ?: @"",
        @"nameSuffix" : nameComponents.nameSuffix ?: @"",
        @"nickname" : nameComponents.nickname ?: @""
    };
}

- (void)authorizationController:(ASAuthorizationController *)controller
           didCompleteWithError:(NSError *)error API_AVAILABLE(ios(13.0)) {
    NSLog(@"[SignInWithApple] Authorization error: %@", error.localizedDescription);

    CDVPluginResult *result = [CDVPluginResult resultWithStatus:CDVCommandStatus_ERROR
                                          messageAsDictionary:@{
                                              @"error" : @"ASAUTHORIZATION_ERROR",
                                              @"code" : @(error.code).stringValue ?: @"",
                                              @"localizedDescription" : error.localizedDescription ?: @"",
                                              @"localizedFailureReason" : error.localizedFailureReason ?: @""
                                          }];
    [self.commandDelegate sendPluginResult:result callbackId:self.callbackId];
}

@end