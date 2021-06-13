#include "tcpbind.h"
#include "serve.h"
#include "url.h"

#include <stdlib.h>
#include <sys/wait.h>
#include <unistd.h>
#include <syslog.h>
#include <sys/socket.h>
#include <stdio.h>
#include <tls.h>
#include <err.h>
#include <string.h>

void
writeclient(struct tls *cctx, char *buf)
{
	ssize_t len;
	int ret;

	len = strlen(buf);
	while (len > 0) {
		ret = tls_write(cctx, buf, len);
		if (ret == TLS_WANT_POLLOUT)
			continue;
		if (ret == -1)
			errx(1, "tls_write: %s", tls_error(cctx));
		buf += ret;
		len -= ret;
	}
}

static void
sendfile(struct tls *cctx, struct url *url)
{
	FILE *fp;
	char buf[4096];
	int found = 0;

	fp = fopen("index", "r");
	if (fp == NULL)
		err(1, "fopen index");
	while (fgets(buf, sizeof(buf), fp) != NULL) {
		buf[strcspn(buf, "\r\n")] = '\0';
		if (strcmp(url->file, buf) == 0) {
			found = 1;
			break;
		}
	}
	fclose(fp);
	if (found == 0) {
		writeclient(cctx, "50 not found\r\n");
		return;
	} else {
		writeclient(cctx, "20 text/gemini\r\n");
	}
	fp = fopen(url->file, "r");
	while (fgets(buf, sizeof(buf), fp) != NULL) {
		writeclient(cctx, buf);
	}
	fclose(fp);
}

static char *
read_url(struct tls *cctx)
{
	char c;
	static char buf[1024];
	size_t len;
	int n;

	len = 0;
	do {
		n = tls_read(cctx, &c, sizeof(char));
		if (n == -1)
			errx(1, "tls_read: %s", tls_error(cctx));
		if (n < 0)
			continue;
		if (c == '\r' || c == '\n')
			break;
		buf[len++] = c;
		if (len+1 == sizeof(buf))
			break;
	} while (n > 0 || n == TLS_WANT_POLLIN);

	buf[len] = '\0';

	return buf;
}

int
main(int argc, char *argv[])
{
	int			 sfd;
	struct tls		*server, *cctx;
	struct tls_config	*cfg;
	char			*cert;
	char			*key;
	char			*urlstr;
	struct url		 url;

	if (argc != 3) {
		fprintf(stderr, "%s certfile keyfile\n", argv[0]);
		return -1;
	}

	cert = argv[1];
	key = argv[2];
	
	openlog(argv[0], 0, LOG_DAEMON);

	sfd = tcpbind("0.0.0.0", 1965);

	if ((server = tls_server()) == NULL)
		errx(1, "failed to create TLS server");
	if ((cfg = tls_config_new()) == NULL)
		errx(1, "failed to create TLS server cfg");
	if (tls_config_set_keypair_file(cfg, cert, key) != 0)
		errx(1, "failed to set keypair: %s",
		    tls_config_error(cfg));
	if (tls_configure(server, cfg) != 0)
		errx(1, "failed to configure: %s",
		    tls_error(server));

	for (;;) {
		int fd, status;
		pid_t pid;

		fd = serve(sfd);

		if (tls_accept_socket(server, &cctx, fd) != 0)
			errx(1, "failed to accept: %s",
			    tls_error(server));

		if ((pid = fork()) == 0) {
			alarm(10);	/* session expire time */

			urlstr = read_url(cctx);
			syslog(LOG_INFO, "got url: %s", urlstr);
			if (url_parse(&url, urlstr) != 0) {
				writeclient(cctx, "50 invalid url\r\n");
				syslog(LOG_ERR, "failed to parse url");
			} else {
				sendfile(cctx, &url);
			}
			tls_close(cctx);
			tls_free(cctx);
			shutdown(fd, SHUT_RDWR);
			close(fd);
			_exit(0);
		}
		close(fd);
		if (pid != -1)
			wait(&status);
	}

	return 0;
}
