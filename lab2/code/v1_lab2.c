/*
  FUSE: Filesystem in Userspace
  Copyright (C) 2001-2007  Miklos Szeredi <miklos@szeredi.hu>

  This program can be distributed under the terms of the GNU GPL.
  See the file COPYING.

  gcc -Wall hello.c `pkg-config fuse --cflags --libs` -o hello
*/

#define FUSE_USE_VERSION 26

#include <fuse.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <libssh/libssh.h>
#include <stdlib.h>

static const char *hello_str = "Hello World!\n";
static const char *hello_path = "/lab2";
struct session_details con;

struct session_details {
  ssh_session my_ssh_session;
  int rc;
  int verbosity;
  int port ;
  char *password;
};


static int _getattr(const char *path, struct stat *stbuf)
{
	int res = 0;

       fprintf(stderr, "Inside getattr");	
       perror("Inside getattr");
	memset(stbuf, 0, sizeof(struct stat));
	if (strcmp(path, "/") == 0) {
		stbuf->st_mode = S_IFDIR | 0755;
		stbuf->st_nlink = 2;
	} else if (strcmp(path, hello_path) == 0) {
		stbuf->st_mode = S_IFREG | 0444;
		stbuf->st_nlink = 1;
		stbuf->st_size = strlen(hello_str);
	} else
		res = -ENOENT;

	return res;
}

static int _readdir(const char *path, void *buf, fuse_fill_dir_t filler,
			 off_t offset, struct fuse_file_info *fi)
{
	(void) offset;
	(void) fi;

	if (strcmp(path, "/") != 0)
		return -ENOENT;

	filler(buf, ".", NULL, 0);
	filler(buf, "..", NULL, 0);
	filler(buf, hello_path + 1, NULL, 0);

	return 0;
}

static int _open(const char *path, struct fuse_file_info *fi)
{
	if (strcmp(path, hello_path) != 0)
		return -ENOENT;

	if ((fi->flags & 3) != O_RDONLY)
		return -EACCES;

	return 0;
}

static int _read(const char *path, char *buf, size_t size, off_t offset,
		      struct fuse_file_info *fi)
{
	size_t len;
	(void) fi;
	if(strcmp(path, hello_path) != 0)
		return -ENOENT;

	len = strlen(hello_str);
	if (offset < len) {
		if (offset + size > len)
			size = len - offset;
		memcpy(buf, hello_str + offset, size);
	} else
		size = 0;

	return size;
}

int show_remote_processes(ssh_session session)
{
  ssh_channel channel;
  int rc;
  char buffer[256];
  unsigned int nbytes;
  channel = ssh_channel_new(session);
  if (channel == NULL)
    return SSH_ERROR;
  rc = ssh_channel_open_session(channel);
  if (rc != SSH_OK)
  {
    ssh_channel_free(channel);
    return rc;
  }
  rc = ssh_channel_request_exec(channel, "ps aux");
  if (rc != SSH_OK)
  {
    ssh_channel_close(channel);
    ssh_channel_free(channel);
    return rc;
  }
  nbytes = ssh_channel_read(channel, buffer, sizeof(buffer), 0);
  while (nbytes > 0)
  {
    if (write(1, buffer, nbytes) != nbytes)
    {
      ssh_channel_close(channel);
      ssh_channel_free(channel);
      return SSH_ERROR;
    }
    nbytes = ssh_channel_read(channel, buffer, sizeof(buffer), 0);
  }

  if (nbytes < 0)
  {
   ssh_channel_close(channel);
    ssh_channel_free(channel);
    return SSH_ERROR;
  }
  ssh_channel_send_eof(channel);
  ssh_channel_close(channel);
  ssh_channel_free(channel);
  return SSH_OK;
}




static struct fuse_operations _oper = {
	.getattr	= _getattr,
	.readdir	= _readdir,
	.open		= _open,
	.read		= _read,
};

int main(int argc, char *argv[])
{
        con.verbosity = SSH_LOG_PROTOCOL;
        con.port = 22;
 
        con.my_ssh_session = ssh_new();

        if (con.my_ssh_session == NULL)
            perror("unable to craete a session");
        ssh_options_set(con.my_ssh_session, SSH_OPTIONS_HOST, "localhost");
        ssh_options_set(con.my_ssh_session, SSH_OPTIONS_LOG_VERBOSITY, &con.verbosity);
        ssh_options_set(con.my_ssh_session, SSH_OPTIONS_PORT, &con.port);
        con.rc = ssh_connect(con.my_ssh_session);
        if (con.rc != SSH_OK)
        {
             fprintf(stderr, "Error connecting to localhost: %s\n",
             ssh_get_error(con.my_ssh_session));
        } else{
             fprintf(stderr, "Connection succesful");
        }

        con.password = getpass("Password: ");
        con.rc = ssh_userauth_password(con.my_ssh_session, NULL, con.password);
        if (con.rc != SSH_AUTH_SUCCESS)
        {
              fprintf(stderr, "Error authenticating with password: %s\n",
              ssh_get_error(con.my_ssh_session));
              ssh_disconnect(con.my_ssh_session);
              ssh_free(con.my_ssh_session);
        }

        //show_remote_processes(con.my_ssh_session);
        ssh_disconnect(con.my_ssh_session);
        ssh_free(con.my_ssh_session);



        int res = fuse_main(argc, argv, &_oper, NULL);
        perror("Fuse main called ");
        return res;
}
