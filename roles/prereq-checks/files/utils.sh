function print_header() {
  echo
  echo "$*"
  echo "-------------------"
}

function pad() {
  printf "%$(($SYSINFO_TITLE_WIDTH+1))s" " "
}
