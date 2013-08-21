#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "irc.h"
#include "helper.h"
#include "mpd.h"


void play(Irc server, Parsed_data pdata) {

	char **argv;
	int argc;

	argv = extract_params(pdata.message, &argc);
	if (argc != 1)
		goto cleanup;

	if (strchr(argv[0], '.') == NULL)
		goto cleanup;

	print_cmd_output(server, pdata.target, (char *[]) { SCRIPTDIR "youtube2mp3.sh", argv[0], cfg.mpd_database, NULL });

cleanup:
	free(argv);
}

void playlist(Irc server, Parsed_data pdata) {

	print_cmd_output_unsafe(server, pdata.target, "mpc playlist |" REMOVE_EXTENSION);
}

void history(Irc server, Parsed_data pdata) {

	char cmd[CMDLEN];

	snprintf(cmd, CMDLEN, "ls -t1 %s | head |" REMOVE_EXTENSION, cfg.mpd_database);
	print_cmd_output_unsafe(server, pdata.target, cmd);
}

void current(Irc server, Parsed_data pdata) {

	print_cmd_output_unsafe(server, pdata.target, "mpc current |" REMOVE_EXTENSION);
}

void next(Irc server, Parsed_data pdata) {

	print_cmd_output_unsafe(server, pdata.target, "mpc -q next");
}