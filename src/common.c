#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <stdarg.h>
#include <signal.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <curl/curl.h>
#include <yajl/yajl_tree.h>
#include "irc.h"
#include "common.h"

pid_t main_pid;
yajl_val root;
struct config_options cfg;
bool *mpd_random_mode;

void initialize(int argc, char *argv[]) {

	main_pid = getpid(); // store our process id to help exit_msg function exit appropriately

	// Accept config path as an optional argument
	if (argc > 2)
		exit_msg("Usage: %s [path_to_config]\n", argv[0]);
	else if (argc == 2)
		parse_config(root, argv[1]);
	else
		parse_config(root, "config.json");

	signal(SIGCHLD, SIG_IGN); // Make child processes not leave zombies behind when killed
	signal(SIGPIPE, SIG_IGN); // Handle writing on closed sockets on our own
	curl_global_init(CURL_GLOBAL_ALL); // Initialize curl library

	if ((mpd_random_mode = mmap(NULL, sizeof(bool), PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0)) == MAP_FAILED)
		perror("mmap");

	if (!access(cfg.mpd_random_file, F_OK))
		*mpd_random_mode = true;
}

void cleanup(void) {

	yajl_tree_free(root);
	curl_global_cleanup();
}

bool streq(const char *s1, const char *s2) {

	return strcmp(s1, s2) == 0;
}

bool starts_with(const char *s1, const char *s2) {

	return strncmp(s1, s2, strlen(s2)) == 0;
}

void exit_msg(const char *format, ...) {

	char buf[EXIT_MSGLEN];
	va_list args;

	va_start(args, format);
	sprintf(buf, "%s\n", format);
	vfprintf(stderr, buf, args);
	va_end(args);

	if (getpid() == main_pid)
		exit(EXIT_FAILURE);
	else
		_exit(EXIT_FAILURE);
}

void *_malloc_w(size_t size, const char *caller) {

	void *buffer;

	if (!(buffer = malloc(size)))
		exit_msg("Error: malloc failed in %s", caller);

	return buffer;
}

void *_calloc_w(size_t size, const char *caller) {

	void *buffer;

	if (!(buffer = calloc(1, size)))
		exit_msg("Error: calloc failed in %s", caller);

	return buffer;
}

void *_realloc_w(void *buf, size_t size, const char *caller) {

	void *buffer;

	if (!(buffer = realloc(buf, size)))
		exit_msg("Error: realloc failed in %s", caller);

	return buffer;
}

char **extract_params(char *msg, int *argc) {

	int size;
	char *temp, **argv;
	*argc = 0;

	// Make sure we have at least 1 parameter before proceeding
	if (!msg)
		return NULL;

	// Allocate enough starting space for most bot commands
	argv = malloc_w(STARTSIZE * sizeof(char *));
	size = STARTSIZE;

	// Null terminate the the whole parameters line
	if (!(temp = strrchr(msg, '\r')))
		return argv;
	*temp = '\0';

	// split parameters seperated by space or tab
	argv[*argc] = strtok(msg, " \t");
	while (argv[*argc]) {
		if (*argc == size - 1) { // Double the array if it gets full
			argv = realloc_w(argv, size * 2 * sizeof(char *));
			size *= 2;
		}
		argv[++(*argc)] = strtok(NULL, " \t");
	}
	return argv;
}

int get_int(const char *num, int max) {

	long converted_num;

	if ((converted_num = strtol(num, NULL, 10)) >= max)
		return max;
	else if (converted_num <= 0)
		return 1;
	else
		return converted_num;
}

void print_cmd_output(Irc server, const char *target, char *cmd_args[]) {

	FILE *prog;
	char line[LINELEN];
	size_t len;
	int fd[2];

	if (pipe(fd) < 0) {
		perror("pipe");
		return;
	}

	switch (fork()) {
	case -1:
		perror("fork");
		return;
	case 0:
		close(fd[0]); // Close reading end of the socket

		// Re-open stdout to point to the writting end of our socket
		if (dup2(fd[1], STDOUT_FILENO) != STDOUT_FILENO) {
			perror("dup2");
			return;
		}
		close(fd[1]); // We don't need this anymore
		execvp(cmd_args[0], cmd_args);

		perror("exec failed"); // Exec functions return only on error
		return;
	}
	close(fd[1]); // Close writting end

	// Open socket as FILE stream since we need to print in lines anyway
	if (!(prog = fdopen(fd[0], "r")))
		return;

	// Print line by line the output of the program
	while (fgets(line, LINELEN, prog)) {
		if ((len = strlen(line) - 1) > 1) { // Only print if line is not empty
			line[len] = '\0'; // Remove last newline char (\n) since we add it inside send_message()
			send_message(server, target, "%s", line); // The %s is needed to avoid interpeting format specifiers in output
		}
	}
	fclose(prog);
}

void print_cmd_output_unsafe(Irc server, const char *target, const char *cmd) {

	FILE *prog;
	char line[LINELEN];
	int len;

	// Open the program with arguments specified
	if (!(prog = popen(cmd, "r")))
		return;

	while (fgets(line, LINELEN, prog)) {
		if ((len = strlen(line) - 1) > 1) {
			line[len] = '\0';
			send_message(server, target, "%s", line);
		}
	}
	pclose(prog);
}

STATIC size_t read_file(char **buf, const char *filename) {

	FILE *file;
	struct stat st;
	size_t n = 0;

	if (!(file = fopen(filename, "r"))) {
		fprintf(stderr, "fopen error: ");
		return 0;
	}
	if (fstat(fileno(file), &st) == -1) {
		fprintf(stderr, "fstat fail: ");
		goto cleanup;
	}
	if (!st.st_size || st.st_size > CONFSIZE) {
		fprintf(stderr, "File too small/big: ");
		goto cleanup;
	}
	*buf = malloc_w(st.st_size + 1);
	if ((n = fread(*buf, sizeof(char), st.st_size, file)) != (unsigned) st.st_size) {
		fprintf(stderr, "fread error: ");
		fclose(file);
		return 0;
	}
	(*buf)[st.st_size] = '\0';

cleanup:
	fclose(file);
	return n;
}

void parse_config(yajl_val root, const char *config_file) {

	char errbuf[1024], *buf = NULL, *mpd_path, *mpd_random_file_path, *HOME;
	yajl_val val, array;
	int i;

	if (!read_file(&buf, config_file))
		exit_msg(config_file);

	if (!(root = yajl_tree_parse(buf, errbuf, sizeof(errbuf))))
		exit_msg("%s", errbuf);

	// Free original buffer since we have a duplicate in root now
	free(buf);

	if (!(val        = yajl_tree_get(root, (const char *[]) { "server", NULL },          yajl_t_string))) exit_msg("server: missing / wrong type");
	cfg.server       = YAJL_GET_STRING(val);
	if (!(val        = yajl_tree_get(root, (const char *[]) { "port", NULL },            yajl_t_number))) exit_msg("port: missing / wrong type");
	cfg.port         = YAJL_GET_NUMBER(val);
	if (!(val        = yajl_tree_get(root, (const char *[]) { "nick", NULL },            yajl_t_string))) exit_msg("nick: missing / wrong type");
	cfg.nick         = YAJL_GET_STRING(val);
	if (!(val        = yajl_tree_get(root, (const char *[]) { "user", NULL },            yajl_t_string))) exit_msg("user: missing / wrong type");
	cfg.user         = YAJL_GET_STRING(val);
	if (!(val        = yajl_tree_get(root, (const char *[]) { "nick_pwd", NULL },        yajl_t_string))) exit_msg("nick_pwd: missing / wrong type");
	cfg.nick_pwd     = YAJL_GET_STRING(val);
	if (!(val        = yajl_tree_get(root, (const char *[]) { "bot_version", NULL },     yajl_t_string))) exit_msg("bot_version: missing / wrong type");
	cfg.bot_version  = YAJL_GET_STRING(val);
	if (!(val        = yajl_tree_get(root, (const char *[]) { "github_repo", NULL },     yajl_t_string))) exit_msg("github_repo: missing / wrong type");
	cfg.github_repo  = YAJL_GET_STRING(val);
	if (!(val        = yajl_tree_get(root, (const char *[]) { "quit_message", NULL },    yajl_t_string))) exit_msg("quit_message: missing / wrong type");
	cfg.quit_msg     = YAJL_GET_STRING(val);
	if (!(val        = yajl_tree_get(root, (const char *[]) { "mpd_database", NULL },    yajl_t_string))) exit_msg("mpd_database: missing / wrong type");
	cfg.mpd_database = YAJL_GET_STRING(val);
	if (!(val        = yajl_tree_get(root, (const char *[]) { "murmur_port", NULL },     yajl_t_string))) exit_msg("murmur_port: missing / wrong type");
	cfg.murmur_port  = YAJL_GET_STRING(val);
	if (!(val        = yajl_tree_get(root, (const char *[]) { "mpd_port", NULL },        yajl_t_string))) exit_msg("mpd_port: missing / wrong type");
	cfg.mpd_port     = YAJL_GET_STRING(val);
	if (!(val        = yajl_tree_get(root, (const char *[]) { "mpd_random_file", NULL }, yajl_t_string))) exit_msg("mpd_random_file: missing / wrong type");
	cfg.mpd_random_file = YAJL_GET_STRING(val);

	// Expand tilde '~' by reading the HOME enviroment variable
	HOME = getenv("HOME");
	if (cfg.mpd_database[0] == '~') {
		mpd_path = malloc_w(PATHLEN);
		snprintf(mpd_path, PATHLEN, "%s%s", HOME, cfg.mpd_database + 1);
		cfg.mpd_database = mpd_path;
	}
	if (cfg.mpd_random_file[0] == '~') {
		mpd_random_file_path = malloc_w(PATHLEN);
		snprintf(mpd_random_file_path, PATHLEN, "%s%s", HOME, cfg.mpd_random_file + 1);
		cfg.mpd_random_file = mpd_random_file_path;
	}
	// Only accept true or false value
	if (!(val = yajl_tree_get(root, (const char *[]) { "verbose", NULL }, yajl_t_any))) exit_msg("verbose: missing");
	if (val->type != yajl_t_true && val->type != yajl_t_false) exit_msg("verbose: wrong type");
	cfg.verbose = YAJL_IS_TRUE(val);

	// Get the array of channels
	if (!(array = yajl_tree_get(root, (const char *[]) { "channels", NULL }, yajl_t_array))) exit_msg("channels: missing / wrong type");
	cfg.channels_set = YAJL_GET_ARRAY(array)->len;

	if (cfg.channels_set > MAXCHANS) {
		cfg.channels_set = MAXCHANS;
		fprintf(stderr, "Channel limit reached (%d). Ignoring rest\n", MAXCHANS);
	}
	for (i = 0; i < cfg.channels_set; i++) {
		val = YAJL_GET_ARRAY(array)->values[i];
		cfg.channels[i] = YAJL_GET_STRING(val);
	}

	if (!(array = yajl_tree_get(root, (const char *[]) { "fail_quotes", NULL }, yajl_t_array))) exit_msg("fail_quotes: missing / wrong type");
	cfg.quote_count = YAJL_GET_ARRAY(array)->len;

	for (i = 0; i < cfg.quote_count; i++) {
		val = YAJL_GET_ARRAY(array)->values[i];
		cfg.quotes[i] = YAJL_GET_STRING(val);
	}
}

char *iso8859_7_to_utf8(char *iso) {

	unsigned char *uiso, *utf;
	unsigned int i = 0, y = 0;

	uiso = (unsigned char *) iso;
	utf = malloc_w(strlen(iso) * 2);

	while (uiso[i] != '\0') {
		if (uiso[i] > 0xa0) {
			if (uiso[i] < 0xf0) {
				utf[y] = 0xce;
				utf[y + 1] = uiso[i] - 48;
			}
			else {
				utf[y] = 0xcf;
				utf[y + 1] = uiso[i] - 112;
			}
			y += 2;
		}
		else {
			utf[y] = uiso[i];
			y++;
		}
		i++;
	}
	utf[y] = '\0';
	return (char *) utf;
}
