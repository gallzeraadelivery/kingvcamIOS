#import <UIKit/UIKit.h>
#import <notify.h>
#import <spawn.h>

extern char **environ;

#define KV_LICENSE_PATH  "/var/jb/Library/KingVCam/license.json"
#define KV_DEBUG_LOG     "/var/jb/Library/KingVCam/debug.log"
#define KV_NOTIFY_SHOW   "com.kingvcam.showgate"
#define KV_NOTIFY_ACK    "com.kingvcam.activated"
#define KV_API_URL       @"https://kingvcam.com/v1/auth/login"
#define KV_VALIDATE_URL  @"https://kingvcam.com/v1/auth/validate"
#define KV_DEBUG_API_URL @"https://kingvcam.com/v1/debug/log"
#define KV_STORE_URL     @"https://kingvcam.com"
#define KV_REVALIDATE_INTERVAL 300

static BOOL kv_alert_visible = NO;
static BOOL kv_upload_running = NO;
static BOOL kv_validating = NO;
static BOOL kv_restart_after_ok = NO;
static int kv_ack_token = 0;
static NSMutableString *kv_mem_log;
static NSString *kv_cached_key = nil;
static NSTimeInterval kv_activated_at = 0;
static NSTimeInterval kv_last_sync = 0;

static void kv_append_debug(NSString *message);
static void kv_show_key_prompt(void);
static void kv_show_expired(void);

static UIViewController *kv_top_vc(void) {
    UIWindow *w = nil;
    for (UIScene *scene in UIApplication.sharedApplication.connectedScenes) {
        if ([scene isKindOfClass:[UIWindowScene class]]) {
            for (UIWindow *win in ((UIWindowScene *)scene).windows) {
                if (win.isKeyWindow) { w = win; break; }
            }
            if (w) break;
        }
    }
    if (!w) return nil;
    UIViewController *vc = w.rootViewController;
    while (vc.presentedViewController) vc = vc.presentedViewController;
    return vc;
}

static NSDictionary *kv_read_license(void) {
    NSData *data = [NSData dataWithContentsOfFile:@(KV_LICENSE_PATH)];
    if (!data) {
        if (kv_cached_key.length > 0) {
            return @{
                @"key": kv_cached_key,
                @"activated_at": @(kv_activated_at),
                @"last_validated": @(kv_activated_at)
            };
        }
        return nil;
    }
    NSDictionary *dict = [NSJSONSerialization JSONObjectWithData:data options:0 error:nil];
    if ([dict isKindOfClass:[NSDictionary class]]) {
        NSString *key = [dict[@"key"] isKindOfClass:[NSString class]] ? dict[@"key"] : @"";
        if (key.length > 0) kv_cached_key = key;
        return dict;
    }
    kv_append_debug(@"license_read_json_fail");
    if (kv_cached_key.length > 0) {
        return @{@"key": kv_cached_key, @"last_validated": @(kv_activated_at)};
    }
    return nil;
}

static BOOL kv_license_file_exists(void) {
    return [[NSFileManager defaultManager] fileExistsAtPath:@(KV_LICENSE_PATH)];
}

static BOOL kv_license_is_active(void) {
    if (kv_cached_key.length > 0) return YES;
    if (kv_license_file_exists()) return YES;
    return kv_read_license() != nil;
}

static void kv_sync_log_online_force(void);

static void kv_append_debug(NSString *message) {
    if (!kv_mem_log) kv_mem_log = [NSMutableString string];
    NSString *line = [NSString stringWithFormat:@"%@ %@\n",
        @((long long)[[NSDate date] timeIntervalSince1970]), message ?: @""];
    [kv_mem_log appendString:line];
    if (kv_mem_log.length > 64000) {
        [kv_mem_log deleteCharactersInRange:NSMakeRange(0, kv_mem_log.length - 64000)];
    }

    NSFileManager *fm = [NSFileManager defaultManager];
    [fm createDirectoryAtPath:@"/var/jb/Library/KingVCam"
        withIntermediateDirectories:YES attributes:nil error:nil];
    NSFileHandle *fh = [NSFileHandle fileHandleForWritingAtPath:@(KV_DEBUG_LOG)];
    if (!fh) {
        [line writeToFile:@(KV_DEBUG_LOG) atomically:NO encoding:NSUTF8StringEncoding error:nil];
        return;
    }
    @try {
        [fh seekToEndOfFile];
        [fh writeData:[line dataUsingEncoding:NSUTF8StringEncoding]];
        [fh closeFile];
    } @catch (__unused NSException *e) {
    }
}

static void kv_upload_debug_log_attempt(NSInteger attempt);
static void kv_upload_debug_log(void);

static NSString *kv_read_debug_log_text(void) {
    NSData *data = [NSData dataWithContentsOfFile:@(KV_DEBUG_LOG)];
    if (!data || data.length == 0) return @"";
    NSString *logText = [[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding];
    return logText ?: @"";
}

static NSString *kv_debug_payload(void) {
    NSMutableString *out = [NSMutableString string];
    if (kv_mem_log.length > 0) [out appendString:kv_mem_log];
    NSString *fileText = kv_read_debug_log_text();
    if (fileText.length > 0 && [out rangeOfString:fileText].location == NSNotFound) {
        [out appendString:fileText];
    }
    if (out.length == 0) [out appendString:@"(sem log local)\n"];
    return out;
}

static void kv_ping_log_via_validate(void) {
    NSString *logText = kv_debug_payload();

    NSDictionary *lic = kv_read_license();
    NSString *key = [lic[@"key"] isKindOfClass:[NSString class]] ? lic[@"key"] : @"";
    NSDictionary *body = @{
        @"device_id": @"ios",
        @"key": key ?: @"",
        @"debug_log": logText
    };
    NSData *json = [NSJSONSerialization dataWithJSONObject:body options:0 error:nil];
    if (!json) return;

    NSMutableURLRequest *req = [NSMutableURLRequest requestWithURL:[NSURL URLWithString:KV_VALIDATE_URL]];
    req.HTTPMethod = @"POST";
    req.timeoutInterval = 20;
    [req setValue:@"application/json" forHTTPHeaderField:@"Content-Type"];
    req.HTTPBody = json;

    [[[NSURLSession sharedSession] dataTaskWithRequest:req
        completionHandler:^(NSData *data, NSURLResponse *resp, NSError *err) {
            NSInteger code = 0;
            if ([resp isKindOfClass:[NSHTTPURLResponse class]]) {
                code = [(NSHTTPURLResponse *)resp statusCode];
            }
            dispatch_async(dispatch_get_main_queue(), ^{
                kv_append_debug([NSString stringWithFormat:@"ping_validate code=%ld err=%@",
                    (long)code, err.localizedDescription ?: @""]);
            });
        }] resume];
}

static void kv_sync_log_online(void) {
    NSTimeInterval now = [[NSDate date] timeIntervalSince1970];
    if (now - kv_last_sync < 2.0) return;
    kv_last_sync = now;
    kv_sync_log_online_force();
}

static void kv_sync_log_online_force(void) {
    kv_ping_log_via_validate();
    kv_upload_debug_log();
}

static void kv_upload_debug_log(void) {
    if (kv_upload_running) return;
    kv_upload_running = YES;
    kv_upload_debug_log_attempt(0);
}

static void kv_upload_debug_log_attempt(NSInteger attempt) {
    NSString *logText = kv_debug_payload();
    if (logText.length == 0) {
        kv_append_debug([NSString stringWithFormat:@"upload_skip empty attempt=%ld", (long)attempt]);
        if (attempt == 0) {
            dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 5 * NSEC_PER_SEC),
                dispatch_get_main_queue(), ^{
                    kv_upload_debug_log_attempt(1);
                });
        } else {
            kv_upload_running = NO;
        }
        return;
    }

    NSDictionary *lic = kv_read_license();
    NSString *key = [lic[@"key"] isKindOfClass:[NSString class]] ? lic[@"key"] : @"";
    NSDictionary *body = @{
        @"device_id": @"ios",
        @"key": key ?: @"",
        @"log": logText ?: @""
    };
    NSData *json = [NSJSONSerialization dataWithJSONObject:body options:0 error:nil];
    if (!json) {
        kv_append_debug([NSString stringWithFormat:@"upload_skip json attempt=%ld", (long)attempt]);
        kv_upload_running = NO;
        return;
    }

    kv_append_debug([NSString stringWithFormat:@"upload_start attempt=%ld bytes=%lu",
        (long)attempt, (unsigned long)json.length]);

    NSMutableURLRequest *req = [NSMutableURLRequest requestWithURL:[NSURL URLWithString:KV_DEBUG_API_URL]];
    req.HTTPMethod = @"POST";
    req.timeoutInterval = 20;
    [req setValue:@"application/json" forHTTPHeaderField:@"Content-Type"];
    req.HTTPBody = json;

    [[[NSURLSession sharedSession] dataTaskWithRequest:req
        completionHandler:^(NSData *respData, NSURLResponse *resp, NSError *err) {
            NSInteger code = 0;
            if ([resp isKindOfClass:[NSHTTPURLResponse class]]) {
                code = [(NSHTTPURLResponse *)resp statusCode];
            }
            BOOL ok = (!err && code >= 200 && code < 300);
            dispatch_async(dispatch_get_main_queue(), ^{
                if (ok) {
                    kv_append_debug([NSString stringWithFormat:@"upload_ok attempt=%ld code=%ld",
                        (long)attempt, (long)code]);
                    kv_upload_running = NO;
                    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 2 * NSEC_PER_SEC),
                        dispatch_get_main_queue(), ^{
                            kv_sync_log_online();
                        });
                } else {
                    kv_append_debug([NSString stringWithFormat:@"upload_fail attempt=%ld code=%ld err=%@",
                        (long)attempt, (long)code, err.localizedDescription ?: @""]);
                    if (attempt < 6) {
                        dispatch_after(dispatch_time(DISPATCH_TIME_NOW, (attempt + 1) * 4 * NSEC_PER_SEC),
                            dispatch_get_main_queue(), ^{
                                kv_upload_debug_log_attempt(attempt + 1);
                            });
                    } else {
                        kv_upload_running = NO;
                    }
                }
            });
        }] resume];
}

static int kv_spawn_killall(const char *path, const char *signal) {
    pid_t pid = 0;
    if (signal) {
        const char *argv[] = {path, signal, "mediaserverd", NULL};
        return posix_spawn(&pid, path, NULL, NULL, (char *const *)argv, environ);
    }
    const char *argv[] = {path, "mediaserverd", NULL};
    return posix_spawn(&pid, path, NULL, NULL, (char *const *)argv, environ);
}

static int kv_spawn_launchctl(const char *path) {
    pid_t pid = 0;
    const char *argv[] = {path, "kickstart", "-k", "system/com.apple.mediaserverd", NULL};
    return posix_spawn(&pid, path, NULL, NULL, (char *const *)argv, environ);
}

static void kv_restart_mediaserverd_once(void) {
    int rc1 = kv_spawn_killall("/var/jb/usr/bin/killall", NULL);
    int rc2 = kv_spawn_killall("/var/jb/usr/bin/killall", "-9");
    int rc3 = kv_spawn_launchctl("/var/jb/usr/bin/launchctl");
    int rc4 = kv_spawn_launchctl("/var/jb/basebin/launchctl");
    int rc5 = kv_spawn_launchctl("/bin/launchctl");
    int rc6 = kv_spawn_killall("/usr/bin/killall", "-9");
    kv_append_debug([NSString stringWithFormat:
        @"restart_once jb=%d jb9=%d jbl=%d bbl=%d lctl=%d usr9=%d",
        rc1, rc2, rc3, rc4, rc5, rc6]);
}

static void kv_restart_mediaserverd(void) {
    kv_restart_mediaserverd_once();
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 1500 * NSEC_PER_MSEC),
        dispatch_get_main_queue(), ^{
            kv_restart_mediaserverd_once();
            kv_append_debug(@"restart_mediaserverd pass2");
            kv_sync_log_online_force();
        });
    kv_sync_log_online_force();
}

static void kv_apply_license_permissions(void) {
    NSFileManager *fm = [NSFileManager defaultManager];
    [fm setAttributes:@{ NSFilePosixPermissions: @0777 }
        ofItemAtPath:@"/var/jb/Library/KingVCam" error:nil];
    if (kv_license_file_exists()) {
        [fm setAttributes:@{ NSFilePosixPermissions: @0666 }
            ofItemAtPath:@(KV_LICENSE_PATH) error:nil];
    }
}

static void kv_write_license(NSString *key) {
    NSFileManager *fm = [NSFileManager defaultManager];
    NSString *dir = @"/var/jb/Library/KingVCam";
    [fm createDirectoryAtPath:dir
        withIntermediateDirectories:YES
        attributes:@{ NSFilePosixPermissions: @0777 }
        error:nil];
    [fm setAttributes:@{ NSFilePosixPermissions: @0777 } ofItemAtPath:dir error:nil];

    kv_cached_key = [key copy];
    kv_activated_at = [[NSDate date] timeIntervalSince1970];
    NSDictionary *dict = @{
        @"key": key ?: @"",
        @"activated_at": @(kv_activated_at),
        @"last_validated": @(kv_activated_at)
    };
    NSData *json = [NSJSONSerialization dataWithJSONObject:dict options:NSJSONWritingPrettyPrinted error:nil];
    NSError *writeErr = nil;
    BOOL ok = [json writeToFile:@(KV_LICENSE_PATH)
        options:NSDataWritingAtomic
        error:&writeErr];
    if (!ok) {
        ok = [fm createFileAtPath:@(KV_LICENSE_PATH)
            contents:json
            attributes:@{ NSFilePosixPermissions: @0666 }];
    }
    kv_apply_license_permissions();
    [fm setAttributes:@{ NSFilePosixPermissions: @0666 } ofItemAtPath:@(KV_LICENSE_PATH) error:nil];

    unsigned long long size = 0;
    if (kv_license_file_exists()) {
        NSDictionary *attrs = [fm attributesOfItemAtPath:@(KV_LICENSE_PATH) error:nil];
        size = [attrs[NSFileSize] unsignedLongLongValue];
    }
    kv_append_debug([NSString stringWithFormat:@"license_saved key=%@ ok=%d bytes=%llu exists=%d err=%@",
        key ?: @"", ok && kv_license_file_exists(), size, kv_license_file_exists(),
        writeErr.localizedDescription ?: @""]);
}

static void kv_validate_key(NSString *key, BOOL isRevalidation);
static BOOL kv_validate_key_sync(NSString *key);

static void kv_revoke_local(void) {
    kv_cached_key = nil;
    kv_activated_at = 0;
    [[NSFileManager defaultManager] removeItemAtPath:@(KV_LICENSE_PATH) error:nil];
    kv_append_debug(@"license_revoked_local");
    kv_restart_mediaserverd();
}

static void kv_update_last_validated(void) {
    NSMutableDictionary *dict = [kv_read_license() mutableCopy];
    if (!dict) return;
    dict[@"last_validated"] = @([[NSDate date] timeIntervalSince1970]);
    NSData *json = [NSJSONSerialization dataWithJSONObject:dict options:NSJSONWritingPrettyPrinted error:nil];
    [json writeToFile:@(KV_LICENSE_PATH) atomically:YES];
    kv_apply_license_permissions();
    kv_append_debug(@"license_revalidated");
}

static BOOL kv_validate_key_sync(NSString *key) {
    if (key.length == 0) return NO;
    __block BOOL ok = NO;
    dispatch_semaphore_t sem = dispatch_semaphore_create(0);
    NSMutableDictionary *body = [@{
        @"key": key ?: @"",
        @"device_id": @"ios"
    } mutableCopy];
    NSString *logText = kv_debug_payload();
    if (logText.length > 0) body[@"debug_log"] = logText;
    NSData *json = [NSJSONSerialization dataWithJSONObject:body options:0 error:nil];
    NSMutableURLRequest *req = [NSMutableURLRequest requestWithURL:[NSURL URLWithString:KV_API_URL]];
    req.HTTPMethod = @"POST";
    req.timeoutInterval = 12;
    [req setValue:@"application/json" forHTTPHeaderField:@"Content-Type"];
    req.HTTPBody = json;
    NSURLSessionDataTask *task = [[NSURLSession sharedSession]
        dataTaskWithRequest:req
        completionHandler:^(NSData *data, NSURLResponse *resp, NSError *err) {
            NSInteger code = 0;
            if ([resp isKindOfClass:[NSHTTPURLResponse class]]) {
                code = [(NSHTTPURLResponse *)resp statusCode];
            }
            if (data && !err) {
                NSDictionary *dict = [NSJSONSerialization JSONObjectWithData:data options:0 error:nil];
                if ([dict isKindOfClass:[NSDictionary class]]) {
                    ok = [dict[@"ok"] boolValue] || [dict[@"authorized"] boolValue];
                }
            }
            kv_append_debug([NSString stringWithFormat:@"validate_sync ok=%d code=%ld err=%@",
                ok, (long)code, err.localizedDescription ?: @""]);
            dispatch_semaphore_signal(sem);
        }];
    [task resume];
    dispatch_semaphore_wait(sem, dispatch_time(DISPATCH_TIME_NOW, 14 * NSEC_PER_SEC));
    return ok;
}

static void kv_validate_key(NSString *key, BOOL isRevalidation) {
    if (kv_validating) {
        kv_append_debug(@"validate_skip busy");
        return;
    }
    kv_validating = YES;
    kv_append_debug([NSString stringWithFormat:@"validate_start revalidation=%d key=%@", isRevalidation, key ?: @""]);
    kv_sync_log_online_force();
    dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_DEFAULT, 0), ^{
        NSMutableDictionary *body = [@{
            @"key": key ?: @"",
            @"device_id": @"ios"
        } mutableCopy];
        NSString *logText = kv_debug_payload();
        if (logText.length > 0) body[@"debug_log"] = logText;
        NSData *json = [NSJSONSerialization dataWithJSONObject:body options:0 error:nil];
        NSURL *url = [NSURL URLWithString:KV_API_URL];
        NSMutableURLRequest *req = [NSMutableURLRequest requestWithURL:url];
        req.HTTPMethod = @"POST";
        req.timeoutInterval = 15;
        [req setValue:@"application/json" forHTTPHeaderField:@"Content-Type"];
        req.HTTPBody = json;

        NSURLSession *session = [NSURLSession sharedSession];
        [[session dataTaskWithRequest:req completionHandler:^(NSData *data, NSURLResponse *resp, NSError *err) {
            BOOL ok = NO;
            NSInteger code = 0;
            if ([resp isKindOfClass:[NSHTTPURLResponse class]]) {
                code = [(NSHTTPURLResponse *)resp statusCode];
            }
            if (data && !err) {
                NSDictionary *dict = [NSJSONSerialization JSONObjectWithData:data options:0 error:nil];
                if ([dict isKindOfClass:[NSDictionary class]]) {
                    ok = [dict[@"ok"] boolValue] || [dict[@"authorized"] boolValue];
                }
            }

            dispatch_async(dispatch_get_main_queue(), ^{
                kv_validating = NO;
                kv_append_debug([NSString stringWithFormat:@"validate_result ok=%d code=%ld revalidation=%d err=%@",
                    ok, (long)code, isRevalidation, err.localizedDescription ?: @""]);
                if (ok) {
                    if (isRevalidation) {
                        kv_update_last_validated();
                        if (kv_restart_after_ok) {
                            kv_restart_after_ok = NO;
                            kv_restart_mediaserverd();
                        }
                    } else {
                        kv_write_license(key);
                        notify_post(KV_NOTIFY_ACK);
                        kv_append_debug(@"activation_ack_posted");
                        kv_restart_mediaserverd();

                        UIAlertController *success = [UIAlertController
                            alertControllerWithTitle:@"kingvcam.com"
                            message:@"Ativado com sucesso!\nAgora tente novamente o volume ou o flutuante."
                            preferredStyle:UIAlertControllerStyleAlert];
                        [success addAction:[UIAlertAction actionWithTitle:@"OK"
                            style:UIAlertActionStyleDefault handler:^(UIAlertAction *a) {
                                kv_alert_visible = NO;
                                kv_sync_log_online();
                            }]];
                        UIViewController *top = kv_top_vc();
                        if (top) [top presentViewController:success animated:YES completion:nil];
                        else kv_alert_visible = NO;
                    }
                    kv_sync_log_online_force();
                } else {
                    kv_sync_log_online_force();
                    if (isRevalidation) {
                        if (err) {
                            kv_append_debug(@"revalidate_network_fail");
                            kv_restart_after_ok = NO;
                            return;
                        }
                        kv_revoke_local();
                        kv_show_expired();
                    } else {
                        UIAlertController *fail = [UIAlertController
                            alertControllerWithTitle:@"Chave Inválida"
                            message:@"Verifique sua chave ou adquira uma licença em kingvcam.com"
                            preferredStyle:UIAlertControllerStyleAlert];
                        [fail addAction:[UIAlertAction actionWithTitle:@"Tentar Novamente"
                            style:UIAlertActionStyleDefault handler:^(UIAlertAction *a) {
                                kv_alert_visible = NO;
                                kv_show_key_prompt();
                            }]];
                        [fail addAction:[UIAlertAction actionWithTitle:@"Comprar Licença"
                            style:UIAlertActionStyleCancel handler:^(UIAlertAction *a) {
                                [[UIApplication sharedApplication] openURL:[NSURL URLWithString:KV_STORE_URL]
                                    options:@{} completionHandler:nil];
                                kv_alert_visible = NO;
                            }]];
                        UIViewController *top = kv_top_vc();
                        if (top) [top presentViewController:fail animated:YES completion:nil];
                        else kv_alert_visible = NO;
                    }
                }
            });
        }] resume];
    });
}

static void kv_handle_showgate(void) {
    kv_alert_visible = NO;
    kv_append_debug(@"notify_show_received");
    if (kv_ack_token) notify_set_state(kv_ack_token, 0);

    if (kv_license_is_active()) {
        NSDictionary *lic = kv_read_license();
        NSString *key = [lic[@"key"] isKindOfClass:[NSString class]] ? lic[@"key"] : @"";
        if (key.length > 0) {
            kv_append_debug(@"notify_show_revalidate_sync");
            BOOL ok = kv_validate_key_sync(key);
            if (ok) {
                kv_update_last_validated();
                if (kv_ack_token) notify_set_state(kv_ack_token, 1);
                notify_post(KV_NOTIFY_ACK);
                kv_append_debug(@"activation_ack_posted_sync_no_restart");
            } else {
                if (kv_ack_token) notify_set_state(kv_ack_token, 0);
                kv_revoke_local();
                dispatch_async(dispatch_get_main_queue(), ^{
                    kv_show_expired();
                });
            }
            kv_sync_log_online_force();
            return;
        }
        kv_revoke_local();
        kv_show_key_prompt();
        kv_sync_log_online_force();
        return;
    }

    kv_append_debug(@"notify_show_no_license");
    kv_show_key_prompt();
}

static void kv_show_key_prompt(void) {
    if (kv_license_is_active()) {
        kv_append_debug(@"show_prompt_blocked_revalidate");
        NSDictionary *lic = kv_read_license();
        NSString *key = [lic[@"key"] isKindOfClass:[NSString class]] ? lic[@"key"] : @"";
        if (key.length > 0) {
            kv_restart_after_ok = NO;
            kv_validate_key(key, YES);
        }
        return;
    }
    if (kv_alert_visible) return;
    kv_alert_visible = YES;
    kv_append_debug(@"show_prompt");
    kv_sync_log_online();

    dispatch_async(dispatch_get_main_queue(), ^{
        UIAlertController *alert = [UIAlertController
            alertControllerWithTitle:@"kingvcam.com"
            message:@"Digite sua chave de ativação"
            preferredStyle:UIAlertControllerStyleAlert];

        [alert addTextFieldWithConfigurationHandler:^(UITextField *tf) {
            tf.placeholder = @"KV-XXXX-XXXX-XXXX";
            tf.autocapitalizationType = UITextAutocapitalizationTypeAllCharacters;
            tf.autocorrectionType = UITextAutocorrectionTypeNo;
        }];

        [alert addAction:[UIAlertAction actionWithTitle:@"Ativar"
            style:UIAlertActionStyleDefault
            handler:^(UIAlertAction *action) {
                NSString *key = alert.textFields.firstObject.text;
                if (key.length == 0) {
                    kv_alert_visible = NO;
                    kv_show_key_prompt();
                    return;
                }
                kv_validate_key(key, NO);
            }]];

        [alert addAction:[UIAlertAction actionWithTitle:@"Comprar Licença"
            style:UIAlertActionStyleCancel
            handler:^(UIAlertAction *action) {
                [[UIApplication sharedApplication] openURL:[NSURL URLWithString:KV_STORE_URL]
                    options:@{} completionHandler:nil];
                kv_alert_visible = NO;
            }]];

        UIViewController *top = kv_top_vc();
        if (top) {
            [top presentViewController:alert animated:YES completion:nil];
        } else {
            kv_alert_visible = NO;
        }
    });
}

static void kv_show_expired(void) {
    if (kv_alert_visible) return;
    kv_alert_visible = YES;
    kv_append_debug(@"show_expired");
    kv_sync_log_online();

    dispatch_async(dispatch_get_main_queue(), ^{
        UIAlertController *alert = [UIAlertController
            alertControllerWithTitle:@"kingvcam.com"
            message:@"Sua licença expirou.\nRenove para continuar usando."
            preferredStyle:UIAlertControllerStyleAlert];

        [alert addAction:[UIAlertAction actionWithTitle:@"Digitar Nova Chave"
            style:UIAlertActionStyleDefault
            handler:^(UIAlertAction *a) {
                kv_alert_visible = NO;
                kv_show_key_prompt();
            }]];

        [alert addAction:[UIAlertAction actionWithTitle:@"Comprar Licença"
            style:UIAlertActionStyleCancel
            handler:^(UIAlertAction *a) {
                [[UIApplication sharedApplication] openURL:[NSURL URLWithString:KV_STORE_URL]
                    options:@{} completionHandler:nil];
                kv_alert_visible = NO;
            }]];

        UIViewController *top = kv_top_vc();
        if (top) [top presentViewController:alert animated:YES completion:nil];
        else kv_alert_visible = NO;
    });
}

static void kv_revalidate_if_needed(void) {
    NSDictionary *lic = kv_read_license();
    if (!lic) {
        kv_append_debug(@"revalidate_skip no_license");
        kv_sync_log_online();
        return;
    }
    NSString *key = lic[@"key"];
    if (key.length == 0) return;
    kv_append_debug(@"revalidate_always");
    kv_restart_after_ok = NO;
    kv_validate_key(key, YES);
}

static void kv_schedule_periodic_revalidate(void) {
    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, KV_REVALIDATE_INTERVAL * NSEC_PER_SEC),
        dispatch_get_main_queue(), ^{
            kv_revalidate_if_needed();
            kv_schedule_periodic_revalidate();
        });
}

%ctor {
    kv_append_debug(@"gate_ctor v2.2.29");
    kv_sync_log_online_force();
    notify_register_check(KV_NOTIFY_ACK, &kv_ack_token);
    int token = 0;
    notify_register_dispatch(KV_NOTIFY_SHOW, &token,
        dispatch_get_main_queue(), ^(int t) {
            kv_handle_showgate();
        });

    dispatch_after(dispatch_time(DISPATCH_TIME_NOW, 3*NSEC_PER_SEC),
        dispatch_get_main_queue(), ^{
            kv_revalidate_if_needed();
        });
    kv_schedule_periodic_revalidate();
}
