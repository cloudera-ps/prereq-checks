#!/usr/bin/env bash

# Script that builds the single file version of the prereq-checks script.
#
# Having just one file makes it easier to distribute and work with, whereas
# keeping multiple files for development makes it easier to maintain.

# http://redsymbol.net/articles/unofficial-bash-strict-mode/
set -euo pipefail

function info() {
    echo "$(tput bold; date) $(tput sgr0)[INFO] $*"
}

function show_usage() {
    SCRIPTNAME=$(basename "${BASH_SOURCE[0]}")
    echo "$(tput bold)NAME:$(tput sgr0)"
    echo "  ${SCRIPTNAME} - prereq-check.sh build script"
    echo
    echo "$(tput bold)SYNOPSIS:$(tput sgr0)"
    echo "  ${SCRIPTNAME} [options]"
    echo
    echo "$(tput bold)OPTIONS:$(tput sgr0)"
    echo "  -h, --help"
    echo "    Show this message"
    echo
    echo "  -a, --auto-build"
    echo "    Watch dependencies for changes and automatically rebuild on changes"
    exit 1
}

function autobuild() {
    if which shellcheck >/dev/null; then
        info "Found 'shellcheck', will run post-build Bash lint"
    else
        info "'shellcheck' not installed, skipping post-build Bash lint"
    fi
    info "Watching dependencies for changes..."
    CMD="ls -l lib/*.sh lib/security/*.sh prereq-check-dev.sh"
    prev=$($CMD)
    while true; do
      sleep 1
      curr=$($CMD)
      if [ "$curr" != "$prev" ]; then
        ./build.sh
        prev="$curr"
      fi
    done
}

opt_usage=
if [[ $# -gt 0 ]]; then
    opt="$1"
    case "$opt" in
        -h|--help)
            opt_usage=true
            ;;
        -a|--auto-build)
            autobuild
            exit 0
            ;;
        *)
            opt_usage=true
            echo
            >&2 echo "ERROR: Unknown option - $opt"
            echo
            ;;
    esac
fi

if [[ $opt_usage ]]; then
    show_usage
    exit 1
fi

IN_FILE=prereq-check-dev.sh
OUT_FILE=prereq-check.sh
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
headerline=$(grep "^# Include libs (START)" "$IN_FILE" -n | cut -d':' -f1)
footerline=$(grep "^# Include libs (STOP)"  "$IN_FILE" -n | cut -d':' -f1)

# Get all the content from $IN_FILE up to the header line to $OUT_FILE.
head -n$((headerline-1)) "$IN_FILE" > "$OUT_FILE"

# Insert comment and link to the latest single file script (what we're building
# here) to $OUT_FILE.
{   echo "# Latest version at:"
    echo "#   https://raw.githubusercontent.com/cloudera-ps/prereq-checks/master/prereq-check.sh"
    echo
} >> "$OUT_FILE"

cldap=lib/security/cldap.pl
{   echo "# $(basename "$cldap") ------------------------------------------------"
    echo "cat << 'EOF' > /tmp/prereq-checks-cldap.pl"
    cat "$cldap"
    echo "EOF"
    echo
} >> "$OUT_FILE"

# Loop through each of the Bash script dependencies in lib/ and embedded them in
# $OUT_FILE.
for lib in $DIR/lib/{security/,}*.sh; do
    {   echo "# $(basename "$lib") ------------------------------------------------"
        cat "$lib"
        echo
    } >> "$OUT_FILE"
done

# Get the rest of the contents from $IN_FILE from footer line onwards to
# $OUT_FILE.
{   echo "# $IN_FILE (main) ------------------------------------------------"
    tail -n+$((footerline+1)) "$IN_FILE"
} >> "$OUT_FILE"
chmod +x "$OUT_FILE"

# Update hard links for Vagrant test boxes
for subdir in vagrant/*/; do
    ln -f prereq-check.sh "$subdir"
done

info "Wrote to $OUT_FILE and updated Vagrant hard-links"

if which shellcheck >/dev/null; then
    info "Running 'shellcheck prereq-check.sh'..."
    set +e
    if shellcheck prereq-check.sh; then
        info "shellcheck: All good"
    else
        info "shellcheck: Found above warnings/errors"
    fi
    set -e
fi
