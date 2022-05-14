/*
 *  log.m
 *  p0laris
 *
 *  created on 1/21/22
 */

#import <Foundation/Foundation.h>
#import "ViewController.h"
#import "common.h"
#import "log.h"

FILE* log_fp = NULL;

void flush_all_the_streams(void) {
    fflush(stdout);
    fflush(stderr);
}

void lprintf(char* s, ...) {
    flush_all_the_streams();
    
    if (log_fp == NULL) {
        /*
         *  log_fp not opened yet
         */
        
        char* open_this = NULL;
        asprintf(&open_this, "/untether/docs/p0laris-%ld.txt", time(NULL));
        
        /*
         *  open it
         */
        log_fp = fopen(open_this, "w");
        if (!log_fp) {
            /*
             *  not untethered yet
             */
            NSArray *paths = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES);
            NSString *documentsDirectory = [paths firstObject];
            char* doc_dir = (char*)[documentsDirectory UTF8String];
            asprintf(&open_this, "%s/p0laris-%ld.txt", doc_dir, time(NULL));
            log_fp = fopen(open_this, "w");
        }
        
//        dup2(log_fp->_file, 2);
//        dup2(log_fp->_file, 1);
//        dup2(log_fp->_file, 0);
    }
    
    char* msg = NULL;
    va_list ap;
    time_t rawtime;
    struct tm* timeinfo;

    time(&rawtime);
    timeinfo = localtime(&rawtime);
    
    va_start(ap, s);
    vasprintf(&msg, s, ap);
    
    char* time_str = asctime(timeinfo);
    for (int i = 0; i < strlen(time_str) + 2; i++) {
        /*
         *  asctime adds a newline at the end, replace
         *  it with a null to end the string
         */
        if (time_str[i] == '\n') {
            time_str[i] = '\0';
            break;
        }
    }

#if 0
    if (log_fp) {
        fprintf(log_fp, "[*] p0laris @ %s: %s\n", time_str, msg);
        fflush(log_fp);
    }
#endif
    
    NSLog(@"[*] p0laris @ %s: %s", time_str, msg);
    
    va_end(ap);
    free(msg);
    
    flush_all_the_streams();
}

int internal_progress_ui(char* msg) {
    /*
     *  this function just updates the status label with `msg`
     *  dispatch_sync so no fun little race conditions
     *  please don't try to break my code it hurts my feelings
     */
    
    int ret = 0;
    dispatch_async(dispatch_get_main_queue(), ^{
        set_label_text(msg);
    });
    
    return ret;
}

int progress(const char* s, ...) {
    /*
     *  this is basically a wrapper for lprintf,
     *  but is still here because i don't feel like updating things
     */
    
    flush_all_the_streams();
    
    int ret = 0;
    char *msg = NULL;
    va_list ap;
    
    va_start(ap, s);
    vasprintf(&msg, s, ap);
    
    lprintf(msg);
    
    ret = strlen(msg);
    va_end(ap);
    free(msg);
    
    return ret;
}

int progress_ui(const char* s, ...) {
    /*
     *  same as progress except it updates the text label
     *  use sparingly
     */
    
    flush_all_the_streams();
    
    int ret = 0;
    char *msg = NULL;
    va_list ap;
    
    va_start(ap, s);
    vasprintf(&msg, s, ap);

    if (!global_untethered)
        internal_progress_ui(msg);
    
    lprintf(msg);
    
    ret = strlen(msg);
    va_end(ap);
    free(msg);
    
    return ret;
}
