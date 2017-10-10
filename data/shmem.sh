#!/bin/bash

set -e;

sudo kextutil -b net.siguza.hsp4;
sudo kmap -e | grep 24K | grep 'mem tru'
sudo kmap -e | grep 00d/;
