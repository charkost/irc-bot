#include <stdio.h>
#include <stdlib.h>
#include <curl/curl.h>
#include "irc.h"
#include "helper.h"


int main(void) {

	Irc freenode;
	char *line, nick_pwd[NICKLEN];
	Parsed_data pdata;
	curl_global_init(CURL_GLOBAL_ALL);

	line = malloc_w(IRCLEN * sizeof(char) + 1); // Space for null char
	pdata = malloc_w(sizeof(*pdata));

	freenode = connect_server("kornbluth.freenode.net", "6667");
	if (freenode == NULL)
		exit_msg("Irc connection failed");

	set_nick(freenode, "fossbot");
	set_user(freenode, "bot");
	printf("Enter nick identify password: ");
	if (scanf("%15s", nick_pwd) != EOF) // Don't try to identify if password is not given
		identify_nick(freenode, nick_pwd);
	join_channel(freenode, "foss-teimes");

	// Keep running as long the connection is active and act on any registered actions found
	while (get_line(freenode, line) > 0)
		parse_line(freenode, line, pdata);

	free(line);
	free(pdata);
	quit_server(freenode, "bye");
	curl_global_cleanup();
	return 0;
}