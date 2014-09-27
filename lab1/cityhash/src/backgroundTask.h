#include<stdio.h>
#include<signal.h>
#include<stdlib.h>
#include <unistd.h>

static int NUMPROCESSES;
static pid_t *processIds;

int start(int numProcesses)
{
       // printf("into Start");
	int i, j;
	if(NUMPROCESSES > 0)
	{
		return -1;
	}
	NUMPROCESSES = numProcesses;

	processIds = (int *) malloc(NUMPROCESSES * sizeof(pid_t));
	if(processIds == NULL)
	{
		printf("Unable to allocate space for processId array.\n");
		return -1;
	}
	for(i = 0; i < NUMPROCESSES; i++)
	{
		pid_t retValue = fork();
                if(((int)retValue) < 0)
		{
			printf("Failed to fork child process, killing others...\n");
			for(j = 0; j < i; j++)
			{
				if(kill(processIds[j], SIGINT) == -1)
				{
					printf("Failed to kill process with id %d\n", ((int)processIds[i]));
				}
			}
			return -1;
		}
	
		if(((int)retValue) == 0)
		{
			while(1);
		}
		else
		{
			//printf("created background %d\n", retValue);
                        processIds[i] = retValue;
		}
	}
	return 0;
}

int stop()
{
	int i;
	for(i = 0; i < NUMPROCESSES; i++)
	{
		if(kill(processIds[i], SIGINT) < 0)
		{
			printf("Failed to kill process with id %d\n", ((int)processIds[i]));
		return -1;
		}
	//printf("\nKilled background : %d" , i);
        }
	NUMPROCESSES = 0;
	return 0;
}

