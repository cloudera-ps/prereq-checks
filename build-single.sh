#!/usr/bin/env bash

IN_FILE=prereq-check.sh

OUT_FILE="${IN_FILE%.*}-single.sh"
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
head=`grep "^# Include libs (START)" $IN_FILE -n | cut -d':' -f1`
foot=`grep "^# Include libs (STOP)"  $IN_FILE -n | cut -d':' -f1`

head -n$(($head-1)) $IN_FILE > $OUT_FILE
for lib in $DIR/lib/*.sh; do
  { echo "# `basename \"$lib\"` ------------------------------------------------"
    cat "$lib"
    echo
  } >> $OUT_FILE
done
{ echo "# $IN_FILE  ------------------------------------------------"
  tail -n+$(($foot+1)) $IN_FILE
} >> $OUT_FILE
chmod +x $OUT_FILE
