#import <Foundation/Foundation.h>
#import <Security/Security.h>
#import <mach-o/dyld.h>
#import <objc/runtime.h>

static NSString *const kTargetBundleID = @"com.toyopagroup.picaboo";
static NSString *const kCloneAppGroup  = @"group.com.toyopagroup.picaboo.clone1";
static NSString *const kDylibName      = @"SnapCloneEngine.dylib";

#pragma mark - 1. Dynamic Bundle Identifier Spoofing (Obj-C & CoreFoundation)

%hook NSBundle
- (NSString *)bundleIdentifier {
    return kTargetBundleID;
}

- (NSDictionary *)infoDictionary {
    // فصل استدعاء %orig في متغير مستقل لمنع خطأ المترجم (expected identifier)
    NSDictionary *origDict = %orig;
    NSMutableDictionary *dict = [origDict mutableCopy];
    if (dict) {
        dict[(NSString *)kCFBundleIdentifierKey] = kTargetBundleID;
    }
    return dict;
}

- (id)objectForInfoDictionaryKey:(NSString *)key {
    if ([key isEqualToString:(NSString *)kCFBundleIdentifierKey]) {
        return kTargetBundleID;
    }
    return %orig;
}
%end

// C-API Hooking لضمان التوافق مع المكتبات التي لا تستخدم NSBundle
%hookf(CFStringRef, CFBundleGetIdentifier, CFBundleRef bundle) {
    return (__bridge CFStringRef)kTargetBundleID;
}

#pragma mark - 2. Keychain Isolation & Redirection

%hookf(OSStatus, SecItemAdd, CFDictionaryRef attributes, CFTypeRef *result) {
    NSMutableDictionary *dict = [(__bridge NSDictionary *)attributes mutableCopy];
    if (dict) {
        dict[(__bridge id)kSecAttrAccessGroup] = kCloneAppGroup;
    }
    return %orig((__bridge CFDictionaryRef)dict, result);
}

%hookf(OSStatus, SecItemCopyMatching, CFDictionaryRef query, CFTypeRef *result) {
    NSMutableDictionary *dict = [(__bridge NSDictionary *)query mutableCopy];
    if (dict) {
        dict[(__bridge id)kSecAttrAccessGroup] = kCloneAppGroup;
    }
    return %orig((__bridge CFDictionaryRef)dict, result);
}

%hookf(OSStatus, SecItemUpdate, CFDictionaryRef query, CFDictionaryRef attributesToUpdate) {
    NSMutableDictionary *dictQuery = [(__bridge NSDictionary *)query mutableCopy];
    if (dictQuery) {
        dictQuery[(__bridge id)kSecAttrAccessGroup] = kCloneAppGroup;
    }
    return %orig((__bridge CFDictionaryRef)dictQuery, attributesToUpdate);
}

#pragma mark - 3. Anti-Tweak / Dyld Image Cloaking

%hookf(uint32_t, _dyld_image_count) {
    uint32_t count = %orig;
    return count > 0 ? count - 1 : count;
}

%hookf(const char *, _dyld_get_image_name, uint32_t image_index) {
    const char *name = %orig(image_index);
    if (name && strstr(name, [kDylibName UTF8String])) {
        return "/System/Library/Frameworks/Foundation.framework/Foundation";
    }
    return name;
}

#pragma mark - 4. Early Constructor Initialization

%ctor {
    @autoreleasepool {
        %init;
    }
}
