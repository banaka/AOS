#!/bin/sh
max=10;
i=1;

while [ $max -gt $i ]
do 
    $i = $i+1; 
    ./a.out 2 3 1 0 0 >> out.txt ; 
done
