#!/bin/sh

PWD=$(pwd)
arch=`uname -m`
archver=`cat /proc/cpuinfo | grep architecture | sed -n '1p' | awk -F ':' '{printf $2}'`
if [ "$arch" == "mips" ];then
	tool=mitool_mipsle
else
	if [ $archver == 8 ];then
		tool=mitool_arm64
	else
		tool=mitool_arm
	fi
fi
if [ "$1" == "unlock" ];then
	$PWD/$tool unlock
elif [ "$1" == "hack" ];then
	$PWD/$tool hack
elif [ "$1" == "lock" ];then
	$PWD/$tool lock
elif [ "$1" == "password" ];then
	$PWD/$tool password
elif [ "$1" == "model" ];then
	$PWD/$tool model
elif [ "$1" == "sn" ];then
	$PWD/$tool sn
elif [ "$1" == "setsn" ];then
	$PWD/$tool setsn $2
else
	echo "what?"
fi
