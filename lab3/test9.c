#include<stdio.h>
int x[5000000];

int main(){
	int i = 0;
	x[0] = 1;
	for(i=1; i< 5000000; i++){
	 	x[i] =+ x[i-1];
	}
	printf("\nx:%d\n", x[4999999]);
	return 0;
}
