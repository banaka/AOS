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
#define PATH_MAX 128

struct session_details {
  ssh_session ssh;
  sftp_session sftp;
  int verbosity;
  int port ;
  char *password;
  char *user;
  char *host;
  char *mountpath;
  char localpath[PATH_MAX];
};

//Extract the Dir or File exact name 
static char* get_remotefilelocation(char *path){
        char *filePath = (char *) malloc(PATH_MAX);
        strcpy(filePath, con.mountpath);
        strcat(filePath, path);
        return filePath;
}

static char* get_localfilelocation(char *path){
	char *filePath = (char *) malloc(PATH_MAX);
  	strcpy(filePath, con.localpath);
  	strcat(filePath, path);
	return filePath;
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
	const char *remotepath = get_remotefilelocation(path);//get_remote_path(path);
        fprintf(stderr,"path %s \n", remotepath);
        
        sftp_attributes attr = sftp_lstat(con.sftp, remotepath);
        if( attr !=NULL){
                fprintf(stderr, "Attr size %d", sizeof(attr));
                memset(stbuf, 0, sizeof(struct stat));
                stbuf->st_uid = attr->uid;
                stbuf->st_gid = attr->gid;
                stbuf->st_atime = attr->atime;
                stbuf->st_ctime = attr->createtime;
                stbuf->st_mtime = attr->mtime;
                stbuf->st_size = attr->size;
                stbuf->st_mode = attr->permissions;
                fprintf(stderr, "stbuf created ");
                sftp_attributes_free(attr);
		res = SSH_OK;
        } else{
		res = SSH_ERROR;
	}
	return EXIT_SUCCESS;
/*	int res;
	res = lstat(path, stbuf);
	if (res == -1)
		return -errno;
*/
}

static int xmp_readlink(const char *path, char *buf, size_t size)
{
	int res;
	const char *remotepath = get_remotefilelocation(path); //get_remote_path(path);
        fprintf(stderr,"path %s \n", remotepath);

	res = sftp_readlink(con.sftp, remotepath);
	if (res == -1)
		return -errno;

	buf[res] = '\0';
	return EXIT_SUCCESS;
}

static int xmp_opendir(const char *path, struct fuse_file_info *fi){
        //umask(0);
        const char *remotepath = get_remotefilelocation(path); //get_remote_path(path);
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
  	 
    	return EXIT_SUCCESS;
}

static int xmp_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
		       off_t offset, struct fuse_file_info *fi)
{
        //umask(0);
        int res = 0;

	const char *remotepath = get_remotefilelocation(path); //get_remote_path(path);
        fprintf(stderr,"path %s \n", remotepath);
	sftp_dir dir;

        (void) offset;
        (void) fi;

        dir = sftp_opendir(con.sftp, remotepath);
        if(dir != NULL){
		sftp_attributes attr;
		perror("readdir loop ");
        	while ( ( attr = sftp_readdir(con.sftp, dir) ) !=NULL){
                	fprintf(stderr, "Attr created");
                	struct stat stbuf;
                	stbuf.st_uid = attr->uid;
                	stbuf.st_gid = attr->gid;
                	stbuf.st_atime = attr->atime;
                	stbuf.st_ctime = attr->createtime;
                	stbuf.st_mtime = attr->mtime;
                	stbuf.st_size = attr->size;
                	stbuf.st_mode = attr->permissions;
                	fprintf(stderr, "stbuf created \n");
			//sftp_attributes_free(attr);
               		res = SSH_OK;
			if (filler(buf, attr->name, &stbuf, 0))
				break;
        	}
		sftp_close(dir);
	} else{
		res = SSH_ERROR;
	}

        return EXIT_SUCCESS;
}

static int xmp_mkdir(const char *path, mode_t mode)
{
	//umask(0);
	int res;
	const char *remotepath = get_remotefilelocation(path);
	fprintf(stderr, "Dir name %s\n", remotepath); 	
	res = sftp_mkdir(con.sftp, remotepath, mode);
	perror("Called mkdir");
	//res = mkdir(path, mode);
	if (res != SSH_OK){
		fprintf(stderr,"Cannot Create dir\n"); 
		return SSH_ERROR;
	}
	return EXIT_SUCCESS;
}

static int xmp_unlink(const char *path)
{
	int res;
	const char *remotepath = get_remotefilelocation(path);

	res = sftp_unlink(con.sftp, remotepath);
	//res = unlink(path);
	if (res == -1)
		return -errno;

	return EXIT_SUCCESS;
}

static int xmp_rmdir(const char *path)
{
	int res;
        const char *remotepath = get_remotefilelocation(path); //get_remote_path(path);
        fprintf(stderr,"path %s \n", remotepath);
	res = sftp_rmdir(con.sftp, remotepath);
	//res = rmdir(path);
	if (res == -1)
		return -errno;

	return EXIT_SUCCESS;
}

static int xmp_symlink(const char *from, const char *to)
{
	int res;
        const char *remotefrom = get_remotefilelocation(from);
        const char *remoteto = get_remotefilelocation(to);

	res = sftp_symlink(con.sftp, remotefrom, remoteto);
	//res = symlink(from, to);
	if (res == -1)
		return -errno;

	return EXIT_SUCCESS;
}

static int xmp_rename(const char *from, const char *to)
{
	int res;
        const char *remotefrom = get_remotefilelocation(from);
        const char *remoteto = get_remotefilelocation(to); 

	res = sftp_rename(con.sftp, remotefrom, remoteto);
	//res = rename(from, to);
	if (res == -1)
		return -errno;

	return EXIT_SUCCESS;
}

static int xmp_chmod(const char *path, mode_t mode)
{
	int res;
        const char *remotepath = get_remotefilelocation(path);
	
	res = sftp_chmod(con.sftp, remotepath, mode);
	//res = chmod(path, mode);
	if (res == -1)
		return -errno;

	return EXIT_SUCCESS;
}

static int xmp_chown(const char *path, uid_t uid, gid_t gid)
{
	int res;
	const char *remotepath = get_remotefilelocation(path);

	res = sftp_chown(con.sftp, remotepath, uid, gid);
	//res = lchown(path, uid, gid);
	if (res == -1)
		return -errno;

	return EXIT_SUCCESS;
}


static int sftp_read_sync(const char* path, int access_type, mode_t mode)
{
	int res;
        sftp_file file;
        char buffer[MAX_XFER_BUF_SIZE];
        int nbytes, nwritten, rc;
        int fd;
	
	const char *remotepath = get_remotefilelocation(path);
	fprintf(stderr, "Open: Remote path %s\n", remotepath);
        
	file = sftp_open(con.sftp, remotepath, access_type, mode);
        if (file == NULL ) {
                fprintf(stderr, "Can't open file for reading: %s\n",
                ssh_get_error(con.ssh));
                return SSH_ERROR;
        } 

        const char *localpath = get_localfilelocation(path);
        fd = open(localpath, access_type, mode); //O_CREAT | O_RDWR , S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH );
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
        res = sftp_close(file);
        if (res != SSH_OK) {
                fprintf(stderr, "Can't close the read file: %s\n",
                ssh_get_error(con.ssh));
                return res;
        }
  return EXIT_SUCCESS;
}


static int xmp_open(const char *path, struct fuse_file_info *fi)
{
    int res;
        sftp_file file;
        char buffer[MAX_XFER_BUF_SIZE];
        int nbytes, nwritten, rc;
        int fd;
	int access_type = O_CREAT | O_RDWR ;
	mode_t mode = S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH ;

        const char *remotepath = get_remotefilelocation(path);
        fprintf(stderr, "Open: Remote path %s\n", remotepath);

        file = sftp_open(con.sftp, remotepath, access_type, mode);
        if (file == NULL ) {
                fprintf(stderr, "Can't open file for reading: %s\n",
                ssh_get_error(con.ssh));
                return SSH_ERROR;
        }

        const char *localpath = get_localfilelocation(path);
        fd = open(localpath, access_type, mode); //O_CREAT | O_RDWR , S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH );
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
        res = sftp_close(file);
	fi->fh = fd;
        if (res != SSH_OK) {
                fprintf(stderr, "Can't close the read file: %s\n",
                ssh_get_error(con.ssh));
                return res;
        }
  return EXIT_SUCCESS;

	//return sftp_read_sync( path, O_CREAT | O_RDWR, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH);
}

static int xmp_read(const char *path, char *buf, size_t size, off_t offset,
		    struct fuse_file_info *fi)
{
	int res;
	
	res = pread(fi->fh, buf, size, offset);
	if (res == -1)
		res = -errno;

	return EXIT_SUCCESS;
}

static int xmp_write(const char *path, const char *buf, size_t size,
		     off_t offset, struct fuse_file_info *fi)
{
	int res;

	res = pwrite(fi->fh, buf, size, offset);
	if (res == -1)
		res = -errno;

	return EXIT_SUCCESS;
}

static int xmp_release (const char *path, struct fuse_file_info *fi){
  	int res; 
  	sftp_file file;
  	char buffer[MAX_XFER_BUF_SIZE];
  	int nbytes, nwritten, rc;
  	//int fd;
	int access_type = O_WRONLY;
	mode_t mode = fi->flags; //S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH ;

	const char *remotepath = get_remotefilelocation(path);

  	file = sftp_open(con.sftp, remotepath, access_type, mode);
  	if (file == NULL) {
      		fprintf(stderr, "Can't open file for writing: %s\n",
              	ssh_get_error(con.ssh));
      		return SSH_ERROR;
  	}
  	
	/*const char *localpath = get_localfilelocation(path);
	fd = open(localpath, O_RDONLY);
	if (fd < 0) {
                fprintf(stderr, "Can't open localfile for writing: %s\n", strerror(errno));
                return -errno;
        }*/
  	for (;;) {
      		nbytes = read(fi->fh, buffer, sizeof(buffer));
      		if (nbytes == 0) {
          		break; // EOF
      		} else if (nbytes < 0) {
          		fprintf(stderr, "Error while reading local file %s\n", strerror(errno));
          		sftp_close(file);
          	return SSH_ERROR;
      		}
     		nwritten = sftp_write(file, buffer, nbytes);
      		if (nwritten != nbytes) {
         		fprintf(stderr, "Error writing in remote: %s\n",
                	ssh_get_error(con.ssh));
          		sftp_close(file);
         		return SSH_ERROR;
      		}
  	}
  	res = sftp_close(file);
  	if (res != SSH_OK) {
      		fprintf(stderr, "Can't close the read file: %s\n",
              	ssh_get_error(con.ssh));
      		return res;
  	}
	
	res = close(fi->fh);

  return EXIT_SUCCESS;
}

//static int xmp_release (const char *path, struct fuse_file_info *fi){

//	return sftp_write_sync(path, O_WRONLY, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH );

//}


static struct fuse_operations xmp_oper = {
	.getattr	= xmp_getattr,
	.readlink	= xmp_readlink,
	.readdir	= xmp_readdir,
	.opendir	= xmp_opendir,
	.mkdir		= xmp_mkdir,
	.symlink	= xmp_symlink,
	.unlink		= xmp_unlink,
	.rmdir		= xmp_rmdir,
	.rename		= xmp_rename,
	.chmod		= xmp_chmod,
	.chown		= xmp_chown,
	.open		= xmp_open,
	.read		= xmp_read,
	.write		= xmp_write,
	.release	= xmp_release,
};



int main(int argc, char *argv[])
{
	//umask(0);

	int res = 0 ;
	con.verbosity = SSH_LOG_PROTOCOL;
        con.user = argv[1];
	con.host = argv[2];
	con.mountpath = argv[3] ;
	con.port = 22;
        con.password = "Sahil18!" ;//"smile";
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
	char *tmp ="/tmp";
	strcpy(con.localpath, tmp);
  	strcat(con.localpath, con.mountpath);

	if (stat(con.localpath, &st) == -1) {
    		//mkdir(con.localpath, 0700);
		fprintf(stderr, "Create the local mount dir %s\n", con.localpath);
		exit(1);
	}

        res = fuse_main(argc, argv, &xmp_oper, NULL);
        perror("Fuse main called ");
        ssh_disconnect(con.ssh);
        sftp_free(con.sftp);
	ssh_free(con.ssh);
        return res;
}
