s/^( fcntl fd=\d+ cmd=F_SETFL) 2050$/$1 O_NONBLOCK\|\.\.\./;
if ($last =~ m/^ fcntl fd=\d+ cmd=F_GETFL$/) {
    s/^ fcntl=2$/ fcntl\=\~O_NONBLOCK\&.../;
}
if ($last =~ m/^ fcntl fd=\d+ cmd=F_SETFL /) {
    s/^ fcntl=0$/ fcntl\=OK/;
}
$last=$_;
