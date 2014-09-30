/*  gcc -Wall fusexmp.c `pkg-config fuse --cflags --libs` -o fusexmp
*/

#define FUSE_USE_VERSION 26

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#ifdef linux
/* For pread()/pwrite()/utimensat() */
#define _XOPEN_SOURCE 700
#endif

#include <fuse.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <dirent.h>
#include <errno.h>
#include <sys/time.h>
#ifdef HAVE_SETXATTR
#include <sys/xattr.h>
#endif

#include <errno.h>
#include <libssh/libssh.h>
#include <stdlib.h>
#include <libssh/sftp.h>
#include <sys/stat.h>


static struct session_details con;

struct session_details {
  ssh_session my_ssh_session;
  sftp_session sftp;
  int rc;
  int verbosity;
  int port ;
  char *password;
  char *user;
  char *mountpath;
};


static char* get_remote_path(char *path){
      char *str = (char *) malloc(1 + strlen(&path)+ strlen(&con.mountpath) );
      strcpy(str, con.mountpath);
      strcat(str, path);
      fprintf(stderr, "%s", str);
return str;
}

static sftp_session create_sftp_session(){
       perror("Inside getattr");
        sftp_session sftp = sftp_new(con.my_ssh_session);
        if (sftp == NULL)
            {
                fprintf(stderr, "Error allocating SFTP session: %s\n",
                ssh_get_error(con.my_ssh_session));
                return NULL;
             }
        perror("sftp established");

        int rc = sftp_init(sftp);
        perror("after init");
        if (rc != SSH_OK)
        {
                fprintf(stderr, "Error initializing SFTP session: %s.\n",
                sftp_get_error(sftp));
                sftp_free(sftp);
                return NULL;
        }
	return sftp;
}

static int xmp_getattr(const char *path, struct stat *stbuf)
{
	umask(0);
        int res = 0;

        fprintf(stderr,"path %s \n", path);
        
        sftp_attributes attr = sftp_lstat(con.sftp, path);
        perror("after lstat");
        if( attr !=NULL){
                fprintf(stderr, "attr size %d", sizeof(attr));
                memset(stbuf, 0, sizeof(struct stat));
                perror("after stbuf memset");
                stbuf->st_uid = attr->uid;
                stbuf->st_gid = attr->gid;
                stbuf->st_atime = attr->atime;
                stbuf->st_ctime = attr->createtime;
                stbuf->st_mtime = attr->mtime;
                stbuf->st_size = attr->size;
                stbuf->st_mode = attr->permissions;
                perror("after assignment to stbuf");
                fprintf(stderr, "stbuf size %d", sizeof(stbuf));
                perror("after stbuf initialization");
                res = SSH_OK;
        } else{
                res = SSH_ERROR;
        }

	return res;
/*	int res;
	res = lstat(path, stbuf);
	if (res == -1)
		return -errno;
*/
}

static int xmp_access(const char *path, int mask)
{
	int res;

	res = access(path, mask);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_readlink(const char *path, char *buf, size_t size)
{
	int res;

	res = readlink(path, buf, size - 1);
	if (res == -1)
		return -errno;

	buf[res] = '\0';
	return 0;
}


static int xmp_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
		       off_t offset, struct fuse_file_info *fi)
{
        umask(0);
        int res = 0;

        fprintf(stderr,"path %s \n", path);
	sftp_dir dir;

        (void) offset;
        (void) fi;

        dir = sftp_opendir(con.sftp, path);
	perror("after opendir");
        if(dir == NULL){
		res = SSH_ERROR;	
	}else{
		sftp_attributes attr;
		perror("readdir loop ");
        	while ( ( attr = sftp_readdir(con.sftp, dir) ) !=NULL){
                	fprintf(stderr, "attr size %d", sizeof(attr));
                	struct stat stbuf;
                	perror("after stbuf memset");
                	stbuf.st_uid = attr->uid;
                	stbuf.st_gid = attr->gid;
                	stbuf.st_atime = attr->atime;
                	stbuf.st_ctime = attr->createtime;
                	stbuf.st_mtime = attr->mtime;
                	stbuf.st_size = attr->size;
                	stbuf.st_mode = attr->permissions;
                	perror("after assignment to stbuf");
                	fprintf(stderr, "stbuf size %d", sizeof(stbuf));
                	perror("after stbuf initialization");
                	res = SSH_OK;
			if (filler(buf, attr->name, &stbuf, 0))
				break;
        	}
		sftp_close(dir);
	}

        return res;

	/*DIR *dp;
	struct dirent *de;

	(void) offset;
	(void) fi;

	dp = opendir(path);
	if (dp == NULL)
		return -errno;

	while ((de = readdir(dp)) != NULL) {
		struct stat st;
		memset(&st, 0, sizeof(st));
		st.st_ino = de->d_ino;
		st.st_mode = de->d_type << 12;
		if (filler(buf, de->d_name, &st, 0))
			break;
	}

	closedir(dp);
	return 0;*/
}

static int xmp_mknod(const char *path, mode_t mode, dev_t rdev)
{
	int res;

	/* On Linux this could just be 'mknod(path, mode, rdev)' but this
	   is more portable */
	if (S_ISREG(mode)) {
		res = open(path, O_CREAT | O_EXCL | O_WRONLY, mode);
		if (res >= 0)
			res = close(res);
	} else if (S_ISFIFO(mode))
		res = mkfifo(path, mode);
	else
		res = mknod(path, mode, rdev);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_mkdir(const char *path, mode_t mode)
{
	umask(0);
	int res;
	path = get_remote_path(path);
	res = sftp_mkdir(con.sftp, path, mode);
	perror("calling mkdir");
	//res = mkdir(path, mode);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_unlink(const char *path)
{
	int res;

	res = unlink(path);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_rmdir(const char *path)
{
	int res;

	res = rmdir(path);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_symlink(const char *from, const char *to)
{
	int res;

	res = symlink(from, to);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_rename(const char *from, const char *to)
{
	int res;

	res = rename(from, to);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_link(const char *from, const char *to)
{
	int res;

	res = link(from, to);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_chmod(const char *path, mode_t mode)
{
	int res;

	res = chmod(path, mode);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_chown(const char *path, uid_t uid, gid_t gid)
{
	int res;

	res = lchown(path, uid, gid);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_truncate(const char *path, off_t size)
{
	int res;

	res = truncate(path, size);
	if (res == -1)
		return -errno;

	return 0;
}

#ifdef HAVE_UTIMENSAT
static int xmp_utimens(const char *path, const struct timespec ts[2])
{
	int res;

	/* don't use utime/utimes since they follow symlinks */
	res = utimensat(0, path, ts, AT_SYMLINK_NOFOLLOW);
	if (res == -1)
		return -errno;

	return 0;
}
#endif

static int xmp_open(const char *path, struct fuse_file_info *fi)
{
	int res;

	res = open(path, fi->flags);
	if (res == -1)
		return -errno;

	close(res);
	return 0;
}

static int xmp_read(const char *path, char *buf, size_t size, off_t offset,
		    struct fuse_file_info *fi)
{
	int fd;
	int res;

	(void) fi;
	fd = open(path, O_RDONLY);
	if (fd == -1)
		return -errno;

	res = pread(fd, buf, size, offset);
	if (res == -1)
		res = -errno;

	close(fd);
	return res;
}

static int xmp_write(const char *path, const char *buf, size_t size,
		     off_t offset, struct fuse_file_info *fi)
{
	int fd;
	int res;

	(void) fi;
	fd = open(path, O_WRONLY);
	if (fd == -1)
		return -errno;

	res = pwrite(fd, buf, size, offset);
	if (res == -1)
		res = -errno;

	close(fd);
	return res;
}

static int xmp_statfs(const char *path, struct statvfs *stbuf)
{
	int res;

	res = statvfs(path, stbuf);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_release(const char *path, struct fuse_file_info *fi)
{
	/* Just a stub.	 This method is optional and can safely be left
	   unimplemented */

	(void) path;
	(void) fi;
	return 0;
}

static int xmp_fsync(const char *path, int isdatasync,
		     struct fuse_file_info *fi)
{
	/* Just a stub.	 This method is optional and can safely be left
	   unimplemented */

	(void) path;
	(void) isdatasync;
	(void) fi;
	return 0;
}

#ifdef HAVE_POSIX_FALLOCATE
static int xmp_fallocate(const char *path, int mode,
			off_t offset, off_t length, struct fuse_file_info *fi)
{
	int fd;
	int res;

	(void) fi;

	if (mode)
		return -EOPNOTSUPP;

	fd = open(path, O_WRONLY);
	if (fd == -1)
		return -errno;

	res = -posix_fallocate(fd, offset, length);

	close(fd);
	return res;
}
#endif

#ifdef HAVE_SETXATTR
/* xattr operations are optional and can safely be left unimplemented */
static int xmp_setxattr(const char *path, const char *name, const char *value,
			size_t size, int flags)
{
	int res = lsetxattr(path, name, value, size, flags);
	if (res == -1)
		return -errno;
	return 0;
}

static int xmp_getxattr(const char *path, const char *name, char *value,
			size_t size)
{
	int res = lgetxattr(path, name, value, size);
	if (res == -1)
		return -errno;
	return res;
}

static int xmp_listxattr(const char *path, char *list, size_t size)
{
	int res = llistxattr(path, list, size);
	if (res == -1)
		return -errno;
	return res;
}

static int xmp_removexattr(const char *path, const char *name)
{
	int res = lremovexattr(path, name);
	if (res == -1)
		return -errno;
	return 0;
}
#endif /* HAVE_SETXATTR */

static struct fuse_operations xmp_oper = {
	.getattr	= xmp_getattr,
	.access		= xmp_access,
	.readlink	= xmp_readlink,
	.readdir	= xmp_readdir,
	.mknod		= xmp_mknod,
	.mkdir		= xmp_mkdir,
	.symlink	= xmp_symlink,
	.unlink		= xmp_unlink,
	.rmdir		= xmp_rmdir,
	.rename		= xmp_rename,
	.link		= xmp_link,
	.chmod		= xmp_chmod,
	.chown		= xmp_chown,
	.truncate	= xmp_truncate,
#ifdef HAVE_UTIMENSAT
	.utimens	= xmp_utimens,
#endif
	.open		= xmp_open,
	.read		= xmp_read,
	.write		= xmp_write,
	.statfs		= xmp_statfs,
	.release	= xmp_release,
	.fsync		= xmp_fsync,
#ifdef HAVE_POSIX_FALLOCATE
	.fallocate	= xmp_fallocate,
#endif
#ifdef HAVE_SETXATTR
	.setxattr	= xmp_setxattr,
	.getxattr	= xmp_getxattr,
	.listxattr	= xmp_listxattr,
	.removexattr	= xmp_removexattr,
#endif
};

int main(int argc, char *argv[])
{
	umask(0);

        con.verbosity = SSH_LOG_PROTOCOL;
        con.port = 22;
	con.user = "bansal";
        con.password = "smile";
        con.my_ssh_session = ssh_new();
	con.mountpath = "/tmp/fuse/";
        if (con.my_ssh_session == NULL)
            perror("unable to craete a session");
        //ssh_options_set(con.my_ssh_session, SSH_OPTIONS_USER, "akanksha");
        //ssh_options_set(con.my_ssh_session, SSH_OPTIONS_HOST, "192.168.1.2");
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

        //con.password = getpass("Password: ");
        con.rc = ssh_userauth_password(con.my_ssh_session, NULL, con.password);
        if (con.rc != SSH_AUTH_SUCCESS)
        {
              fprintf(stderr, "Error authenticating with password: %s\n",
              ssh_get_error(con.my_ssh_session));
              ssh_disconnect(con.my_ssh_session);
              ssh_free(con.my_ssh_session);
        }

	
	con.sftp = create_sftp_session(); 
        int res = fuse_main(argc, argv, &xmp_oper, NULL);
        perror("Fuse main called ");
        ssh_disconnect(con.my_ssh_session);
        sftp_free(con.sftp);
	ssh_free(con.my_ssh_session);
        return res;
}
