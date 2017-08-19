#!/usr/bin/env bash

# Script that builds the single file version of the prereq-checks script.
#
# Having just one file makes it easier to distribute and work with, whereas
# keeping multiple files for development makes it easier to maintain.

IN_FILE=prereq-check.sh
OUT_FILE="${IN_FILE%.*}-single.sh"
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
headerline=`grep "^# Include libs (START)" $IN_FILE -n | cut -d':' -f1`
footerline=`grep "^# Include libs (STOP)"  $IN_FILE -n | cut -d':' -f1`

# Get all the content from $IN_FILE up to the header line to $OUT_FILE.
head -n$(($headerline-1)) $IN_FILE > $OUT_FILE

# Insert comment and link to the latest single file script (what we're building
# here) to $OUT_FILE.
{   echo "# Latest version at:"
    echo "#   https://raw.githubusercontent.com/cloudera-ps/prereq-checks/master/prereq-check-single.sh"
    echo
} >> $OUT_FILE

# Loop through each of the Bash script dependencies in lib/ and embedded them in
# $OUT_FILE.
for lib in $DIR/lib/{security/,}*.sh; do
    {   echo "# `basename \"$lib\"` ------------------------------------------------"
        cat "$lib"
        echo
    } >> $OUT_FILE
done

# Get the rest of the contents from $IN_FILE from footer line onwards to
# $OUT_FILE.
{   echo "# $IN_FILE (main) ------------------------------------------------"
    tail -n+$(($footerline+1)) $IN_FILE
} >> $OUT_FILE
chmod +x $OUT_FILE

# Update hard links for Vagrant test boxes
for subdir in vagrant/*/; do
    ln -f prereq-check-single.sh $subdir
    ln -f lib/security/cldap.pl  $subdir
done
