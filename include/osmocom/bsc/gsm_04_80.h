#pragma once

struct gsm_subscriber_connection;

int bsc_send_ussd_notify(struct gsm_subscriber_connection *conn, int level,
			 const char *text);
int bsc_send_ussd_release_complete(struct gsm_subscriber_connection *conn);
