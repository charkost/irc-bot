#ifndef MPD_H
#define MPD_H

#include "irc.h"
#include <stdbool.h>

/**
 * @file mpd.h
 * Contains the functions to interact with MPD
 * A helper script will be used (youtube2mp3.sh) to do most of the work
 */

#define CMDLEN 100
#define SONGLEN 512
#define SCRIPTDIR "scripts/" //!< default folder to look for scripts like the youtube one

/** Remove file extension. Works with multiple dots in file as well */
#define REMOVE_EXTENSION "gawk -F. -v OFS=. '{NF--; print}'"

/** Download video from youtube, convert it to mp3, feed it to mpd and start streaming in icecast.
 *  If there is no dot '.' on the argument, then a search will be performed.
 *  If there is a single result it will be added to queue, else up to 3 results will be printed */
void play(Irc server, Parsed_data pdata);

/** Current playlist. First song is the one playing.
 *  @warning Disabled in random mode */
void playlist(Irc server, Parsed_data pdata);

/** Previous played songs. First hit is the older one
 *  @warning Disabled in random mode */
void history(Irc server, Parsed_data pdata);

/** Current song */
void current(Irc server, Parsed_data pdata);

/** Skip song and print the title of the next */
void next(Irc server, Parsed_data pdata);

/** Queue up all songs and play them in random mode */
void random_mode(Irc server, Parsed_data pdata);

/** Connect to mpd daemon and verify the reply
 *
 * @param port     MPD's default one is 6600
 * @return         a valid fd or -1 for error
 */
int mpd_connect(const char *port);

/** Announce current song playing in channel. It will only print song if it's not the same as the last one
 *  @warning  It keeps a static array for song comparison. Will restart the query for a next song automatically
 *
 * @param channel  the channel to send to
 */
bool print_song(Irc server, const char *channel);

#endif
