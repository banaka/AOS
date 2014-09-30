#include <libssh/libssh.h> 
#include <stdlib.h>
#include <stdio.h>

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

int main()
{
  ssh_session my_ssh_session;
  int rc;
  int verbosity = SSH_LOG_PROTOCOL;
  int port = 22;
  char *password;
  my_ssh_session = ssh_new();
  
  if (my_ssh_session == NULL)
    exit(-1);
  ssh_options_set(my_ssh_session, SSH_OPTIONS_HOST, "localhost");
  ssh_options_set(my_ssh_session, SSH_OPTIONS_LOG_VERBOSITY, &verbosity);
  ssh_options_set(my_ssh_session, SSH_OPTIONS_PORT, &port);
  rc = ssh_connect(my_ssh_session);
  if (rc != SSH_OK)
  {
    fprintf(stderr, "Error connecting to localhost: %s\n",
            ssh_get_error(my_ssh_session));
    exit(-1);
  } else{
    fprintf(stderr, "Connection succesful"); 
  }
 
  password = getpass("Password: ");
  rc = ssh_userauth_password(my_ssh_session, NULL, password);
  if (rc != SSH_AUTH_SUCCESS)
  {
    fprintf(stderr, "Error authenticating with password: %s\n",
            ssh_get_error(my_ssh_session));
    ssh_disconnect(my_ssh_session);
    ssh_free(my_ssh_session);
    exit(-1);
  }
 
  show_remote_processes(my_ssh_session); 
  ssh_disconnect(my_ssh_session);
  ssh_free(my_ssh_session);
}
