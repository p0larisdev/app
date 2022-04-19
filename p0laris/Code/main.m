#include <sys/utsname.h>
#include <sys/sysctl.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>

#import "ViewController.h"
#import <UIKit/UIKit.h>
#import "AppDelegate.h"
#import "jailbreak.h"
#import "common.h"
#import "log.h"

#define USBMUX_THE_SHIT_OUT_OF_IT 0
#define USBMUX_THE_SHIT_OUT_OF_IT2 0

#define WAIT_UNTIL 20

bool global_untethered;
double load_uptime = 0.0;

char* no_keep_alive[] = {
    "/usr/libexec/wifiFirmwareLoader",
    "/usr/libexec/wifiFirmwareLoaderLegacy",
};

double uptime(void) {
    /*
     * i'm pretty sure this function is unused, keeping it anyway just in case
     */
    struct timeval boottime;
    size_t len = sizeof(boottime);
    int mib[2] = { CTL_KERN, KERN_BOOTTIME };
    if(sysctl(mib, 2, &boottime, &len, NULL, 0) < 0) {
        return -1.0;
    }
    
    time_t bsec = boottime.tv_sec, csec = time(NULL);

    return difftime(csec, bsec);
}

int go(bool untethered) {
    /*
     * This code will execute when ran by the untether, or when the button is clicked.
     * The untethered argument can be used to determine which.
     */
    
    load_uptime = uptime();
    
#if USBMUX_THE_SHIT_OUT_OF_IT2
    int resultfd, sockfd;
    int port = 1337;
    struct sockaddr_in my_addr;
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    int one = 1;
    setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

    my_addr.sin_family = AF_INET;
    my_addr.sin_port = htons(port);
    my_addr.sin_addr.s_addr = INADDR_ANY;

    bind(sockfd, (struct sockaddr *) &my_addr, sizeof(my_addr));

    listen(sockfd, 0);
    resultfd = accept(sockfd, NULL, NULL);
    
    dup2(resultfd, 2);
    dup2(resultfd, 1);
    dup2(resultfd, 0);
#endif
    
    if (untethered) {
        NSLog(@"I came through a portal holding a 40 and a blunt. Do you really wanna test me right now?");
        lprintf("running untethered, %f", load_uptime);
    }
    else {
        lprintf("running from app");
    }
    
    if (untethered) {
        while (uptime() < WAIT_UNTIL) {
            lprintf("delaying %fs", WAIT_UNTIL - uptime());
            sleep(1);
        }
    }
    
    global_untethered = untethered;
    progress("eta son");
    
    /* do the stuff */
    
    if (!global_untethered) {
        dispatch_async(dispatch_get_global_queue(DISPATCH_QUEUE_PRIORITY_BACKGROUND, 0), ^{
            bool jb = _jailbreak();
            progress("jailbreak(); = %s", jb ? "true" : "false");
            set_button_text("jailbroken");
        });
    } else {
        bool jb = _jailbreak();
        progress("jailbreak(); = %s", jb ? "true" : "false");
        set_button_text("jailbroken");
    }
    
#if 0
    /* stuff is done */
    
    progress("done");
#endif
        
    return 0;
}

int main(int argc, char * argv[]) {
#if USBMUX_THE_SHIT_OUT_OF_IT
    int resultfd, sockfd;
    int port = 1337;
    struct sockaddr_in my_addr;
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    int one = 1;
    setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

    my_addr.sin_family = AF_INET;
    my_addr.sin_port = htons(port);
    my_addr.sin_addr.s_addr = INADDR_ANY;

    bind(sockfd, (struct sockaddr *) &my_addr, sizeof(my_addr));

    listen(sockfd, 0);
    resultfd = accept(sockfd, NULL, NULL);
    
    dup2(resultfd, 2);
    dup2(resultfd, 1);
    dup2(resultfd, 0);
#endif
    printf("p0laris\n"
           "\n"
           "built on %s at %s (%s)\n", __DATE__, __TIME__, __ID_STUFF__);
    if (argc == 1) {
        NSString * appDelegateClassName;
        @autoreleasepool {
            appDelegateClassName = NSStringFromClass([AppDelegate class]);
        }
        return UIApplicationMain(argc, argv, nil, appDelegateClassName);
    }
    else if (argc >= 2) {
        go(true);

        /*
         * i do a sleep(3600) loop in case we're a KeepAlive daemon, in which case
         * exiting might be an issue
         *
         * a real solution is needed, but this works for now
         */

        while (1) {
            sleep(3600);
        }
        return 0;
    }
    else {
        return 0;
    }
}
