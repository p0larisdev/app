/*
 *  log.h
 *  p0laris
 *
 *  created on 1/21/22
 */

#ifndef log_h
#define log_h

int internal_progress_ui(char* msg);

int progress_ui(const char* s, ...);
int progress(const char* s, ...);

void set_button_text(char* s);
void set_label_text(char* s);

void lprintf(char* s, ...);

#endif /* log_h */
