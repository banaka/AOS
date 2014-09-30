/*  
gcc -Wall fusexmp.c `pkg-config fuse --cflags --libs` -o fusexmp
*/

#define FUSE_USE_VERSION 26
#define MAX_XFER_BUF_SIZE 16384

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
  ssh_session ssh;
  sftp_session sftp;
  int verbosity;
  int port ;
  char *password;
  char *user;
  char *host;
  char *mountpath;
};
//Extract the Dir or File exact name 
static char* get_dirlocation(char *path){
	int i = 0;
	int len = strlen(path);
	for ( i=0; i< len; i++){
		if (path[i] != con.mountpath[i])
			break;
	}
	char *str = (char *) malloc( 1 + strlen(con.mountpath) - strlen(path));
	int j = 0;
	for( ; i < len ; i++, j++){
		str[j] = con.mountpath[i];
	}
	str[j] = 0;
	return str;
}

static char* get_remote_path(char *path){
      char *str = (char *) malloc(1 + strlen(&path) + strlen(&con.mountpath) );
      strcpy(str, con.mountpath);
      strcat(str, path + 1);
      fprintf(stderr, " remote path : %s \n ", str);
      return str;
}

static sftp_session create_sftp_session(){
       perror("Inside getattr");
        sftp_session sftp = sftp_new(con.ssh);
        if (sftp == NULL)
            {
                fprintf(stderr, "Error allocating SFTP session: %s\n",
                ssh_get_error(con.ssh));
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
	const char *remotepath = path;//get_remote_path(path);
        fprintf(stderr,"path %s \n", remotepath);
        
        sftp_attributes attr = sftp_lstat(con.sftp, remotepath);
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

static int xmp_opendir(const char *path, struct fuse_file_info *fi){
        umask(0);
        const char *remotepath = path; //get_remote_path(path);
        fprintf(stderr,"path %s \n", remotepath);
        sftp_dir dir;
      
        dir = sftp_opendir(con.sftp, remotepath);
        perror("after opendir");
	if(dir == NULL){
		fprintf(stderr, "Opendir Errro : Directory not opened: %s\n",
         	ssh_get_error(con.ssh));
		return SSH_ERROR;
	}
	fi->fh = (intptr_t) dir;
   
    	return SSH_OK;
}

static int xmp_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
		       off_t offset, struct fuse_file_info *fi)
{
        umask(0);
        int res = 0;

	const char *remotepath = path; //get_remote_path(path);
        fprintf(stderr,"path %s \n", remotepath);
	sftp_dir dir;

        (void) offset;
        (void) fi;

        dir = sftp_opendir(con.sftp, remotepath);
	perror("after opendir");
        if(dir != NULL){
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
	} else{
		res = SSH_ERROR;
	}

        return res;

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
	const char *remotepath = get_dirlocation(path);
	fprintf(stderr, "Dir name %s\n", remotepath); 	
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
	res = sftp_unlink(con.sftp, path);
	//res = unlink(path);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_rmdir(const char *path)
{
	int res;
	res = sftp_rmdir(con.sftp, path);
	//res = rmdir(path);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_symlink(const char *from, const char *to)
{
	int res;
	res = sftp_symlink(con.sftp, from, to);
	//res = symlink(from, to);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_rename(const char *from, const char *to)
{
	int res;
	res = sftp_rename(con.sftp, from, to);
	//res = rename(from, to);
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
	//const char *remotepath = get_remote_path(path);
	res = sftp_chmod(con.sftp, path, mode);
	//res = chmod(path, mode);
	if (res == -1)
		return -errno;

	return 0;
}

static int xmp_chown(const char *path, uid_t uid, gid_t gid)
{
	int res;
	res = sftp_chown(con.sftp, path, uid, gid);
	//res = lchown(path, uid, gid);
	if (res == -1)
		return -errno;

	return 0;
}


static int sftp_read_sync(const char* path)
{
  int access_type;
  sftp_file file;
  char buffer[MAX_XFER_BUF_SIZE];
  int nbytes, nwritten, rc;
  int fd;
  access_type = O_RDONLY;
  file = sftp_open(con.sftp, path, access_type, 0);
  if (file == NULL) {
      fprintf(stderr, "Can't open file for reading: %s\n",
              ssh_get_error(con.ssh));
      return SSH_ERROR;
  }
  fd = open(path, O_CREAT);
  if (fd < 0) {
      fprintf(stderr, "Can't open file for writing: %s\n", strerror(errno));
      return SSH_ERROR;
  }
  for (;;) {
      nbytes = sftp_read(file, buffer, sizeof(buffer));
      if (nbytes == 0) {
          break; // EOF
      } else if (nbytes < 0) {
          fprintf(stderr, "Error while reading file: %s\n",
                  ssh_get_error(con.ssh));
          sftp_close(file);
          return SSH_ERROR;
      }
      nwritten = write(fd, buffer, nbytes);
      if (nwritten != nbytes) {
          fprintf(stderr, "Error writing: %s\n",
                  strerror(errno));
          sftp_close(file);
          return SSH_ERROR;
      }
  }
  rc = sftp_close(file);
  if (rc != SSH_OK) {
      fprintf(stderr, "Can't close the read file: %s\n",
              ssh_get_error(con.ssh));
      return rc;
  }
  return SSH_OK;
}


static int xmp_open(const char *path, struct fuse_file_info *fi)
{
	int res;
	sftp_read_sync(path);
	//res = open(path, fi->flags);
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
	
	//res = statvfs(path, stbuf);
	if (res == -1)
		return -errno;

	return 0;
}



static struct fuse_operations xmp_oper = {
	.getattr	= xmp_getattr,
	//.access		= xmp_access,
	.readlink	= xmp_readlink,
	.readdir	= xmp_readdir,
	.opendir	= xmp_opendir,
	//.mknod		= xmp_mknod,
	.mkdir		= xmp_mkdir,
	.symlink	= xmp_symlink,
	.unlink		= xmp_unlink,
	.rmdir		= xmp_rmdir,
	.rename		= xmp_rename,
	//.link		= xmp_link,
	.chmod		= xmp_chmod,
	.chown		= xmp_chown,
	.open		= xmp_open,
	.read		= xmp_read,
	.write		= xmp_write,
	//.statfs		= xmp_statfs,
};



int main(int argc, char *argv[])
{
	umask(0);

	int res = 0 ;
	con.verbosity = SSH_LOG_PROTOCOL;
        con.user = argv[1];
	con.host = argv[2];
	con.mountpath = argv[3] ;
	con.port = 22;
        con.password = "smile";
	fprintf(stderr, "user %s \n", con.user);
	fprintf(stderr, "mountpatth %s \n", con.mountpath);
	fprintf(stderr, "host %s \n", con.host);
	
	int i = 1;
	for(; i < argc; ++i) {
      		argv[i] = argv[i+2];
    	}
      	argv[argc - 2] = NULL;
      	argc = argc -2;

        con.ssh = ssh_new();
        if (con.ssh == NULL)
            fprintf(stderr, "Unable to create a SSH session");
        ssh_options_set(con.ssh, SSH_OPTIONS_USER, con.user);
        ssh_options_set(con.ssh, SSH_OPTIONS_HOST, con.host );
        ssh_options_set(con.ssh, SSH_OPTIONS_LOG_VERBOSITY, &con.verbosity);
        ssh_options_set(con.ssh, SSH_OPTIONS_PORT, &con.port);
        res = ssh_connect(con.ssh);
        if (res != SSH_OK)
        {
             fprintf(stderr, "Error connecting to localhost: %s\n",
             ssh_get_error(con.ssh));
        } else{
             fprintf(stderr, "Connection succesful");
        }

        //con.password = getpass("Password: ");
        res = ssh_userauth_password(con.ssh, NULL, con.password);
        if (res != SSH_AUTH_SUCCESS)
        {
              fprintf(stderr, "Error authenticating with password: %s\n",
              ssh_get_error(con.ssh));
              ssh_disconnect(con.ssh);
              ssh_free(con.ssh);
        }
	
	con.sftp = create_sftp_session(); 

	struct stat st = {0};
	if (stat(con.mountpath, &st) == -1) {
    		mkdir(con.mountpath, 0700);
	}

        res = fuse_main(argc, argv, &xmp_oper, NULL);
        perror("Fuse main called ");
        ssh_disconnect(con.ssh);
        sftp_free(con.sftp);
	ssh_free(con.ssh);
        return res;
}
