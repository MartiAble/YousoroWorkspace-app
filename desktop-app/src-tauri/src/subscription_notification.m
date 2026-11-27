#import <AppKit/AppKit.h>
#import <dispatch/dispatch.h>
#import <UserNotifications/UserNotifications.h>

static NSString *const Category = @"workspace-renew-subscription";
static NSString *const RenewAction = @"workspace-renew-browser";

@interface WorkspaceSubscriptionNotifications : NSObject <UNUserNotificationCenterDelegate>
@end

@implementation WorkspaceSubscriptionNotifications
- (void)userNotificationCenter:(UNUserNotificationCenter *)center
       willPresentNotification:(UNNotification *)notification
         withCompletionHandler:(void (^)(UNNotificationPresentationOptions))completion {
    if (@available(macOS 11.0, *)) {
        completion(UNNotificationPresentationOptionBanner | UNNotificationPresentationOptionList);
    } else {
        completion(UNNotificationPresentationOptionAlert);
    }
}

- (void)userNotificationCenter:(UNUserNotificationCenter *)center
 didReceiveNotificationResponse:(UNNotificationResponse *)response
         withCompletionHandler:(void (^)(void))completion {
    NSString *action = response.actionIdentifier;
    if ([action isEqualToString:RenewAction] || [action isEqualToString:UNNotificationDefaultActionIdentifier]) {
        NSString *address = response.notification.request.content.userInfo[@"renew_url"];
        NSURL *url = address ? [NSURL URLWithString:address] : nil;
        if ([url.scheme isEqualToString:@"https"] && [url.path isEqualToString:@"/checkout"] &&
            [url.query isEqualToString:@"plan=monthly_renewal"]) {
            dispatch_async(dispatch_get_main_queue(), ^{
                [NSWorkspace.sharedWorkspace openURL:url];
            });
        }
    }
    completion();
}
@end

void workspace_install_subscription_notice_delegate(void) {
    if (!NSBundle.mainBundle.bundleIdentifier) return;
    static WorkspaceSubscriptionNotifications *delegate;
    if (!delegate) delegate = [WorkspaceSubscriptionNotifications new];
    UNUserNotificationCenter.currentNotificationCenter.delegate = delegate;
}

void workspace_subscription_notice(const char *message, const char *renew_url) {
    NSString *body = [NSString stringWithUTF8String:message];
    NSString *url = [NSString stringWithUTF8String:renew_url];
    dispatch_async(dispatch_get_main_queue(), ^{
        if (!NSBundle.mainBundle.bundleIdentifier) return;
        workspace_install_subscription_notice_delegate();
        UNUserNotificationCenter *center = UNUserNotificationCenter.currentNotificationCenter;
        UNNotificationAction *action = [UNNotificationAction actionWithIdentifier:RenewAction
            title:@"Продлить в браузере" options:UNNotificationActionOptionForeground];
        UNNotificationCategory *category = [UNNotificationCategory categoryWithIdentifier:Category
            actions:@[action] intentIdentifiers:@[] options:0];
        [center setNotificationCategories:[NSSet setWithObject:category]];
        [center requestAuthorizationWithOptions:UNAuthorizationOptionAlert
            completionHandler:^(BOOL allowed, NSError *error) {
                if (!allowed) return;
                UNMutableNotificationContent *content = [UNMutableNotificationContent new];
                content.title = @"Yousoro Workspace";
                content.body = body;
                content.categoryIdentifier = Category;
                content.userInfo = @{@"renew_url": url};
                UNNotificationRequest *request = [UNNotificationRequest requestWithIdentifier:Category
                    content:content trigger:nil];
                [center addNotificationRequest:request withCompletionHandler:nil];
            }];
    });
}
