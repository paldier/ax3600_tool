#!/bin/sh

arch=`cat /proc/cpuinfo | grep architecture | sed -n '1p' | awk -F ':' '{printf $2}'`
if [ $arch == 8 ];then
	tool=mitool_arm64
else
	tool=mitool_arm
fi
if [ "$1" == "unlock" ];then
	/tmp/$tool unlock
elif [ "$1" == "hack" ];then
	/tmp/$tool hack
elif [ "$1" == "lock" ];then
	/tmp/$tool lock
elif [ "$1" == "password" ];then
	/tmp/$tool password
elif [ "$1" == "model" ];then
	/tmp/$tool model
else
	echo "what?"
fi
