#!/bin/bash
correct=0
total=0
for file in "$@"
do
    #echo checking $file
    actual=$(sha512sum $file | cut -c-128)
    mine=$(~/rose/csse479/hw12/sha $file)
    if [ "$actual" = "$mine" ]
    then
	correct=$((correct+1))
    else
	echo fail
	echo actual: $actual
	echo mine: $mine
    fi
    total=$((total+1))
done
echo $correct correct out of $total
