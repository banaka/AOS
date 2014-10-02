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

//#include <fuse_lowlevel.h>
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

/**********************SSH RELATED CODE ***********************/
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



int verify_knownhost()
{
    	int state, hlen;
    	unsigned char *hash = NULL;
    	char *hexa;
    	char buf[10];
    	state = ssh_is_server_known(con.ssh);
    	hlen = ssh_get_pubkey_hash(con.ssh, &hash);
    	if (hlen < 0)
        	return -1;
        switch (state)
        {
            case SSH_SERVER_KNOWN_OK:
            	break; /* ok */
            case SSH_SERVER_KNOWN_CHANGED:
            	fprintf(stderr, "Host key for server changed: it is now:\n");
            	ssh_print_hexa("Public key hash", hash, hlen);
            	fprintf(stderr, "For security reasons, connection will be stopped\n");
            	free(hash);
            	return -1;
            case SSH_SERVER_FOUND_OTHER:
            	fprintf(stderr, "The host key for this server was not found but an other"
            	"type of key exists.\n");
            	fprintf(stderr, "An attacker might change the default server key to"
            	"confuse your client into thinking the key does not exist\n");
            	free(hash);
            	return -1;
            case SSH_SERVER_FILE_NOT_FOUND:
            	fprintf(stderr, "Could not find known host file.\n");
            	fprintf(stderr, "If you accept the host key here, the file will be"
            	"automatically created.\n");
            	/* fallback to SSH_SERVER_NOT_KNOWN behavior */
            case SSH_SERVER_NOT_KNOWN:
            	hexa = ssh_get_hexa(hash, hlen);
            	fprintf(stderr,"The server is unknown. Do you trust the host key?\n");
            	fprintf(stderr, "Public key hash: %s\n", hexa);
            	free(hexa);
            	if (fgets(buf, sizeof(buf), stdin) == NULL)
            	{
                	free(hash);
                	return -1;
            	}
            	if (strncasecmp(buf, "yes", 3) != 0)
           	 {
                	free(hash);
                	return -1;
            	}
            	if (ssh_write_knownhost(con.ssh) < 0)
            	{
                	fprintf(stderr, "Error %s\n", strerror(errno));
                	free(hash);
                	return -1;
            	}
            	break;
            case SSH_SERVER_ERROR:
            	fprintf(stderr, "Error %s", ssh_get_error(con.ssh));
            	free(hash);
            	return -1;
        }
        free(hash);
        return 0;
}

/**************************FUSE OVERRIDE METHODS**********************/

/*static void xmp_lookup(fuse_req_t req, fuse_ino_t parent, const char *name)
{
        struct fuse_entry_param e;

        if (parent != 1)
                fuse_reply_err(req, ENOENT);
        else {
                memset(&e, 0, sizeof(e));
                //e.ino = 2;
                //e.attr_timeout = 1.0;
                //e.entry_timeout = 1.0;
                //hello_stat(e.ino, &e.attr);

                fuse_reply_entry(req, &e);
        }
}
*/


static int xmp_getattr(const char *path, struct stat *stbuf)
{
umask(0);
	const char *remotepath = get_remotefilelocation(path);
        fprintf(stderr,"path %s \n", remotepath);
        
        sftp_attributes attr = sftp_lstat(con.sftp, remotepath);
        if( attr !=NULL){
                //fprintf(stderr, "Attr size %d", sizeof(attr));
                memset(stbuf, 0, sizeof(struct stat));
                stbuf->st_uid = attr->uid;
                stbuf->st_gid = attr->gid;
                stbuf->st_atime = attr->atime;
                stbuf->st_ctime = attr->createtime;
                stbuf->st_mtime = attr->mtime;
                stbuf->st_size = attr->size;
                stbuf->st_mode = attr->permissions;
                //fprintf(stderr, "stbuf created ");
                sftp_attributes_free(attr);
        } else{
		return SSH_ERROR;
	}
	return EXIT_SUCCESS;
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
       umask(0); 
        const char *remotepath = get_remotefilelocation(path);
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
umask(0);
        int res = 0;
	const char *remotepath = get_remotefilelocation(path); 
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
umask(0);
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
umask(0);
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
umask(0);
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
umask(0);
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
umask(0);
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
umask(0);
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
umask(0);
	int res;
	const char *remotepath = get_remotefilelocation(path);

	res = sftp_chown(con.sftp, remotepath, uid, gid);
	//res = lchown(path, uid, gid);
	if (res == -1)
		return -errno;

	return EXIT_SUCCESS;
}

static int xmp_open(const char *path, struct fuse_file_info *fi)
{
umask(0);
    	int res;
        sftp_file file;
        char buffer[MAX_XFER_BUF_SIZE];
        int nbytes, nwritten, rc;
        int fd;
	int access_type = O_CREAT | O_RDWR ;
	mode_t mode = S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH ;

        const char *remotepath = get_remotefilelocation(path);
        fprintf(stderr, "Open Remote path: %s\n", remotepath);

        file = sftp_open(con.sftp, remotepath, access_type, mode);
        if (file == NULL ) {
                fprintf(stderr, "Can't open file: %s\n",
                ssh_get_error(con.ssh));
                return SSH_ERROR;
        }

        const char *localpath = get_localfilelocation(path);
        fd = open(localpath, access_type, mode); 
        if (fd < 0) {
                fprintf(stderr, "Can't open local file for caching: %s\n", strerror(errno));
                return SSH_ERROR;
        }
        for (;;) {
                nbytes = sftp_read(file, buffer, sizeof(buffer));
                if (nbytes == 0) {
                        break; // EOF
                } else if (nbytes < 0) {
                        fprintf(stderr, "Error while reading remote file: %s\n",
                        ssh_get_error(con.ssh));
                        sftp_close(file);
                return SSH_ERROR;
        	}
       	 	nwritten = write(fd, buffer, nbytes);
        	if (nwritten != nbytes) {
                	fprintf(stderr, "Error writing into local cache copy: %s\n",
                	strerror(errno));
                	sftp_close(file);
			close(fd);
                	return SSH_ERROR;
        	}
        }
        res = sftp_close(file);
        if (res != SSH_OK) {
                fprintf(stderr, "Can't close the read file: %s\n",
                ssh_get_error(con.ssh));
                return res;
        }
	fi->fh = fd;
  return EXIT_SUCCESS;
}

//Reading / Writting into the local copy of the file. Internally for every read/write operation the file will first be opened and only then call to the read/write operation is made. Because open command has already made a copy of the file we, can just make use of the local file descriptor saved in the fuse_file_info pointer to ensure that corect  local copy is used for the operation. 
static int xmp_read(const char *path, char *buf, size_t size, off_t offset,
		    struct fuse_file_info *fi) {
//umask(0);
	fprintf(stderr, "inside write");

	int res;
	res = pread(fi->fh, buf, size, offset);
	if (res < 0){
		res = -errno;
		return res; 
	}
	return res;
}

static int xmp_write(const char *path, const char *buf, size_t size,
		     off_t offset, struct fuse_file_info *fi) {
//umask(0);
	fprintf(stderr, "inside write");
	int res;
	res = pwrite(fi->fh, buf, size, offset);
	if (res < 0){
		res = -errno;
		return res;
	}
	return res;
}


static int xmp_flush (const char *path, struct fuse_file_info *fi){
//umask(0);
  	int res; 
  	sftp_file file;
  	char buffer[MAX_XFER_BUF_SIZE];
  	int nbytes, nwritten;
	int access_type = O_WRONLY ;
	mode_t mode = S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP | S_IROTH ;

	const char *remotepath = get_remotefilelocation(path);
	//open the remote copy of the machine in write mode so as to be able to write the local copy into remote
  	file = sftp_open(con.sftp, remotepath, access_type, mode);
  	if (file == NULL) {
      		fprintf(stderr, "Can't open file for writing: %s\n",
              	ssh_get_error(con.ssh));
      		return SSH_ERROR;
  	}
	//close(fi->fh);
	int fd = fi->fh; 
	lseek(fi->fh, 0L, SEEK_SET);//lseek(fd, 0, 0);
	//const char *localpath = get_localfilelocation(path);
        //int fd = open(localpath, O_RDONLY, mode);
	if ( fd < 0){
		fprintf(stderr, "Unable to open the local File");
		return SSH_ERROR;
	}
  	//Copy the contents of the local file into the remote machine
  	for (;;) {
      		nbytes = read(fd, buffer, sizeof(buffer));
      		if (nbytes == 0) {
          		break; // EOF
      		} else if (nbytes < 0) {
          		fprintf(stderr, "Error while reading local file %s fd: %d\n", strerror(errno), fd);
          		sftp_close(file);
          	return SSH_ERROR;
      		}
     		nwritten = sftp_write(file, buffer, nbytes);
      		fprintf(stderr,"Written into remote file %d\n",nwritten);
		if (nwritten != nbytes) {
         		fprintf(stderr, "Error writing in remote: %s\n",
                	ssh_get_error(con.ssh));
          		sftp_close(file);
         		return SSH_ERROR;
      		}
  	}
	//close the remote and local copy of the files
  	res = sftp_close(file);
  	if (res != SSH_OK) {
      		fprintf(stderr, "Can't close the file being written : %s\n",
              	ssh_get_error(con.ssh));
      		return res;
  	}
	//fi->fh = fd; 
	//res = close(fd);
  return EXIT_SUCCESS;
}

static int xmp_release (const char *path, struct fuse_file_info *fi){
	//xmp_flush(path, fi);
	const char *localpath = get_localfilelocation(path);
	//Remove any reference to the local 
	unlink(localpath); 
	//close(fi->fh);
	return EXIT_SUCCESS;
}
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
	.flush		= xmp_flush,
	//.lookup		= xmp_lookup,
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
        con.password = "Sahil18!" ;//"smile";
	fprintf(stderr, "user %s \n", con.user);
	fprintf(stderr, "mountpatth %s \n", con.mountpath);
	fprintf(stderr, "host %s \n", con.host);

	//Shifting the arguments so as to make sure that the underlying fuse layer is oblivious to the changes made 	
	int i = 1;
	for(; i < argc; ++i) {
      		argv[i] = argv[i+2];
    	}
      	argv[argc - 2] = NULL;
      	argc = argc -2;

	//verifying connection details and saving the connection details. Source: libssh.org Tutorial
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
	     exit(-1);
        } 
        fprintf(stderr, "Succusful SSH Connection!!!");

 	if (verify_knownhost() < 0)
        {
            fprintf(stderr, "Error verifying the connecting server.");
            ssh_disconnect(con.ssh);
            ssh_free(con.ssh);
            exit(-1);
        }

        //con.password = getpass("Password: ");
        res = ssh_userauth_password(con.ssh, NULL, con.password);
        if (res != SSH_AUTH_SUCCESS)
        {
              fprintf(stderr, "Error authenticating with password: %s\n",
              ssh_get_error(con.ssh));
              ssh_disconnect(con.ssh);
              ssh_free(con.ssh);
	      exit(-1);
        }
	
	con.sftp = create_sftp_session(); 

	//Create a local working directory for the directory being mounted. 
	struct stat st = {0};
	char *tmp ="/tmp";
	strcpy(con.localpath, tmp);
  	strcat(con.localpath, con.mountpath);

	if (stat(con.localpath, &st) == -1 ) {
    		//mkdir(con.localpath, 0700);
		fprintf(stderr, "Unable to Create the local mount dir %s\n", con.localpath);
		exit(-1);
	}

        res = fuse_main(argc, argv, &xmp_oper, NULL);
        ssh_disconnect(con.ssh);
        sftp_free(con.sftp);
	ssh_free(con.ssh);
        return res;
}
