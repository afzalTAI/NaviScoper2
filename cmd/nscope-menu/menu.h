#ifndef NAVI_MENU_H
#define NAVI_MENU_H

/* Implemented in menu.m. */
void navi_menu_run(void);
void navi_menu_stop(void);

/* Implemented in Go via cgo //export; invoked on the main thread only. */
void navi_status_text(char *buf, int n);
int navi_enabled(void);
void navi_toggle(void);
void navi_dashboard_url(char *buf, int n);
void navi_quit(void);

int  navi_route_enabled(void);
void navi_route_toggle(void);

#endif
