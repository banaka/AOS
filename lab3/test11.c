#include<stdio.h>
int x[5000000];

int main(){
	int i = 0;
	x[4999999] = 1;
	for(i = 4999998; i > 0; i--){
	 	x[i] = x[i+1];
	}
	printf("\nx:%d\n", x[1]);
	return 0;
}
