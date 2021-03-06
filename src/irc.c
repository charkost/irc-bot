#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdarg.h>
#include <errno.h>
#include <assert.h>
#include "socket.h"
#include "irc.h"
#include "gperf.h"
#include "common.h"

// Wrapper functions. If VA_ARGS is NULL (last 2 args) then ':' will be ommited. Do not call _irc_command() directly
#define irc_nick_command(server, target)    _irc_command(server, "NICK", target, NULL, (char *) NULL)
#define irc_user_command(server, target)    _irc_command(server, "USER", target, NULL, (char *) NULL)
#define irc_channel_command(server, target) _irc_command(server, "JOIN", target, NULL, (char *) NULL)
#define irc_ping_command(server, target)    _irc_command(server, "PONG", target, NULL, (char *) NULL)
#define irc_quit_command(server, target)    _irc_command(server, "QUIT", "", target,   (char *) NULL)

struct irc_type {
	int sock;
	char line[IRCLEN + 1];
	size_t line_offset;
	char address[ADDRLEN];
	char port[PORTLEN];
	char nick[NICKLEN];
	char user[USERLEN];
	char channels[MAXCHANS][CHANLEN];
	int channels_set;
	bool isConnected;
};

Irc irc_connect(const char *address, const char *port) {

	Irc server = calloc_w(sizeof(*server));

	// Minimum validity checks
	if (!strchr(address, '.') || atoi(port) > 65535)
		return NULL;

	if ((server->sock = sock_connect(address, port)) < 0)
		return NULL;

	fcntl(server->sock, F_SETFL, O_NONBLOCK); // Set socket to non-blocking mode
	strncpy(server->address, address, ADDRLEN);
	strncpy(server->port, port, PORTLEN);

	return server;
}

int get_socket(Irc server) {

	return server->sock;
}

char *default_channel(Irc server) {

	return server->channels[0];
}

void set_nick(Irc server, const char *nick) {

	assert(nick && "Error in set_nick");
	strncpy(server->nick, nick, NICKLEN);
	irc_nick_command(server, server->nick);
}

void set_user(Irc server, const char *user) {

	char user_with_flags[USERLEN * 2 + 6];

	assert(user && "Error in set_user");
	strncpy(server->user, user, USERLEN);

	snprintf(user_with_flags, USERLEN * 2 + 6, "%s 0 * :%s", server->user, server->user);
	irc_user_command(server, user_with_flags);
}

int join_channel(Irc server, const char *channel) {

	int i = 0;

	if (channel) {
		assert(channel[0] == '#' && "Missing # in channel");
		if (server->channels_set == MAXCHANS) {
			fprintf(stderr, "Channel limit reached (%d)\n", MAXCHANS);
			return -1;
		}
		strncpy(server->channels[server->channels_set++], channel, CHANLEN);
		if (server->isConnected)
			irc_channel_command(server, server->channels[server->channels_set - 1]);

		return 1;
	}

	if (server->isConnected)
		for (; i < server->channels_set; i++)
			irc_channel_command(server, server->channels[i]);

	return i;
}

ssize_t parse_irc_line(Irc server) {

	char *test;
	Parsed_data pdata;
	Function_list flist;
	int reply;
	ssize_t n;

	// Read raw line from server. Example: ":laxanofido!~laxanofid@snf-23545.vm.okeanos.grnet.gr PRIVMSG #foss-teimes :How YA doing fossbot"
	if ((n = sock_readline(server->sock, server->line + server->line_offset, IRCLEN - server->line_offset)) <= 0) {
		if (n != -EAGAIN)
			exit_msg("IRC connection closed");

		server->line_offset = strlen(server->line);
		return n;
	}
	server->line_offset = 0;

	if (cfg.verbose)
		fputs(server->line, stdout);

	// Check for server ping request. Example: "PING :wolfe.freenode.net"
	// If we match PING then change the 2nd char to 'O' and terminate the argument before sending back
	if (starts_with(server->line, "PING")) {
		test = strrchr(server->line, '\r');
		*test = '\0';
		irc_ping_command(server, server->line + 5);
		return n;
	}
	// Store the sender of the message / server command without the leading ':'.
	// Examples: "laxanofido!~laxanofid@snf-23545.vm.okeanos.grnet.gr", "wolfe.freenode.net"
	if (!(pdata.sender = strtok(server->line + 1, " ")))
		return n;

	// Store the server command. Examples: "PRIVMSG", "MODE", "433"
	if (!(pdata.command = strtok(NULL, " ")))
		return n;

	// Store everything that comes after the server command
	// Examples: "#foss-teimes :How YA doing fossbot_", "fossbot :How YA doing fossbot"
	if (!(pdata.message = strtok(NULL, "")))
		return n;

	// Initialize the last struct member to silence compiler warnings
	pdata.target = NULL;

	// Find out if server command is a numeric reply
	if (!(reply = atoi(pdata.command))) {
		// Find & launch any functions registered to IRC commands
		if ((flist = function_lookup(pdata.command, strlen(pdata.command))))
			flist->function(server, pdata);
	} else
		numeric_reply(server, reply);

	return n;
}

int numeric_reply(Irc server, int reply) {

	switch (reply) {
	case NICKNAMEINUSE: // Change our nick
		strcat(server->nick, "_");
		set_nick(server, server->nick);
		break;
	case ENDOFMOTD: // Join all channels set before
		server->isConnected = true;
		join_channel(server, NULL);
		break;
	}
	return reply;
}

void irc_privmsg(Irc server, Parsed_data pdata) {

	Function_list flist;
	char *test;

	// Discard hostname from nickname. "laxanofido!~laxanofid@snf-23545.vm.okeanos.grnet.gr" becomes "laxanofido"
	if ((test = strchr(pdata.sender, '!')))
		*test = '\0';

	// Store message destination. Example channel: "#foss-teimes" or private: "fossbot"
	if (!(pdata.target = strtok(pdata.message, " ")))
		return;

	// If target is not a channel, reply on private back to sender instead
	if (!strchr(pdata.target, '#'))
		pdata.target = pdata.sender;

	// Example commands we might receive: ":!url in.gr", ":\x01VERSION\x01"
	if (!(pdata.command = strtok(NULL, " ")))
		return;
	pdata.command++; // Skip leading ":" character

	// Make sure BOT command / CTCP request gets null terminated if there are no parameters
	if (!(pdata.message = strtok(NULL, ""))) {
		test = strrchr(pdata.command, '\r');
		*test = '\0';
	}
	// Bot commands must begin with '!'
	if (*pdata.command == '!') {
		pdata.command++; // Skip leading '!' before passing the command

		// Query our hash table for any functions registered to BOT commands
		if (!(flist = function_lookup(pdata.command, strlen(pdata.command))))
			return;

		// Launch the function in a new process
		switch (fork()) {
		case 0:
			flist->function(server, pdata);
			_exit(EXIT_SUCCESS);
		case -1:
			perror("fork");
		}
	}
	// CTCP requests must begin with ascii char 1
	else if (*pdata.command == '\x01') {
		if (starts_with(pdata.command + 1, "VERSION")) // Skip the leading escape char
			send_notice(server, pdata.sender, "\x01VERSION %s\x01", cfg.bot_version);
	}
}

void irc_notice(Irc server, Parsed_data pdata) {

	bool temp;

	// notice destination
	if (!(pdata.target = strtok(pdata.message, " ")))
		return;

	// Grab the message
	if (!(pdata.message = strtok(NULL, "")))
		return;

	// Skip leading ':'
	pdata.message++;

	if (starts_with(pdata.message, "This nickname is registered")) {
		temp = cfg.verbose;
		cfg.verbose = false;
		send_message(server, "nickserv", "identify %s", cfg.nick_pwd);
		memset(cfg.nick_pwd, 0, strlen(cfg.nick_pwd));
		cfg.verbose = temp;
	}
}

void irc_kick(Irc server, Parsed_data pdata) {

	char *test, *victim;
	int i;

	// Discard hostname from nickname
	if ((test = strchr(pdata.sender, '!')))
		*test = '\0';

	// Which channel did the kick happen
	if (!(pdata.target = strtok(pdata.message, " ")))
		return;

	// Who got kicked
	if (!(victim = strtok(NULL, " ")))
		return;

	// Null terminate victim's nick
	if ((test = strchr(victim, ' ')))
		*test = '\0';

	// Rejoin and send a message back to the one who kicked us
	if (streq(victim, server->nick)) {
		sleep(5);

		// Find the channel we got kicked on and remove it from our list
		// TODO verify if we actually rejoined the channel
		for (i = 0; i < server->channels_set; i++)
			if (streq(pdata.target, server->channels[i]))
				break;

		strncpy(server->channels[i], server->channels[--server->channels_set], CHANLEN);
		join_channel(server, pdata.target);
		send_message(server, pdata.target, "%s magkas...", pdata.sender);
	}
}

void _irc_command(Irc server, const char *type, const char *target, const char *format, ...) {

	va_list args;
	char msg[IRCLEN - 50], irc_msg[IRCLEN];

	va_start(args, format);
	vsnprintf(msg, IRCLEN - 50, format, args);
	if (*msg)
		snprintf(irc_msg, IRCLEN, "%s %s :%s\r\n", type, target, msg);
	else
		snprintf(irc_msg, IRCLEN, "%s %s\r\n", type, target);

	// Send message & print it on stdout
	if (sock_write_non_blocking(server->sock, irc_msg, strlen(irc_msg)) == -1)
		exit_msg("Failed to send message");

	if (cfg.verbose)
		fputs(irc_msg, stdout);

	va_end(args);
}

void quit_server(Irc server, const char *msg) {

	assert(msg && "Error in quit_server");
	irc_quit_command(server, msg);

	if (close(server->sock) < 0)
		perror(__func__);

	free(server);
}
