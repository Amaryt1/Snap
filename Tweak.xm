#import <Foundation/Foundation.h>
#import <Security/Security.h>

static NSString *const kTargetBundleID = @"com.toyopagroup.picaboo";
static NSString *const kCloneAppGroup  = @"group.com.toyopagroup.picaboo.clone1";

#pragma mark - 1. Dynamic Bundle Identifier Spoofing (Obj-C & CoreFoundation)

%hook NSBundle
- (NSString *)bundleIdentifier {
    return kTargetBundleID;
}

- (NSDictionary *)infoDictionary {
    NSDictionary *origDict = %orig;
    if (!origDict) return nil;
    
    NSMutableDictionary *dict = [origDict mutableCopy];
    if (dict) {
        dict[(NSString *)kCFBundleIdentifierKey] = kTargetBundleID;
        return [dict copy]; // إرجاع نسخة ثابتة (Immutable) لمنع أي تعارض في الذاكرة
    }
    return origDict;
}

- (id)objectForInfoDictionaryKey:(NSString *)key {
    if ([key isEqualToString:(NSString *)kCFBundleIdentifierKey]) {
        return kTargetBundleID;
    }
    return %orig;
}
%end

// C-API Hooking لضمان التوافق مع التحققات منخفضة المستوى
%hookf(CFStringRef, CFBundleGetIdentifier, CFBundleRef bundle) {
    return (__bridge CFStringRef)kTargetBundleID;
}

#pragma mark - 2. Keychain Isolation & Redirection

%hookf(OSStatus, SecItemAdd, CFDictionaryRef attributes, CFTypeRef *result) {
    if (!attributes) return %orig(attributes, result);
    NSMutableDictionary *dict = [(__bridge NSDictionary *)attributes mutableCopy];
    if (dict) {
        dict[(__bridge id)kSecAttrAccessGroup] = kCloneAppGroup;
    }
    return %orig((__bridge CFDictionaryRef)dict, result);
}

%hookf(OSStatus, SecItemCopyMatching, CFDictionaryRef query, CFTypeRef *result) {
    if (!query) return %orig(query, result);
    NSMutableDictionary *dict = [(__bridge NSDictionary *)query mutableCopy];
    if (dict) {
        dict[(__bridge id)kSecAttrAccessGroup] = kCloneAppGroup;
    }
    return %orig((__bridge CFDictionaryRef)dict, result);
}

%hookf(OSStatus, SecItemUpdate, CFDictionaryRef query, CFDictionaryRef attributesToUpdate) {
    if (!query) return %orig(query, attributesToUpdate);
    NSMutableDictionary *dictQuery = [(__bridge NSDictionary *)query mutableCopy];
    if (dictQuery) {
        dictQuery[(__bridge id)kSecAttrAccessGroup] = kCloneAppGroup;
    }
    return %orig((__bridge CFDictionaryRef)dictQuery, attributesToUpdate);
}

#pragma mark - 3. Initialization

%ctor {
    @autoreleasepool {
        %init;
    }
}
