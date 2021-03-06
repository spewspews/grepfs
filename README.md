# grepfs
9p filesystem for searching a remote directory.

This fileserver provides an RPC endpoint to search
a remote filesystem.

Start it on your remote fileserver in a listener
```
	aux/listen1 tcp!*!1234 grepfs /path/to/files/*
```
Then you can connect to it with whatever 9p client you
use. For unix, I recommend
[9pfs](https://github.com/spewspew/grepfs)! For plan 9
you connect to it like normal:
```
	srv tcp!remote!1234 grepfs
	mount -a /srv/grepfs .
```
This will put in your directory a single file:
```
	grepctl
```
that accepts regular expressions as follows:
```
	echo -n regex > grepctl
```
That calls grep on the remote server in the directory provided with
the regular expression "regex" that you provided.  The results are
returned by reading the same file:
```
	cat dirnamegrep
```
The following script is helpful:
```
#!/bin/rc
echo -n $1 > grepctl
cat grepctl
```
