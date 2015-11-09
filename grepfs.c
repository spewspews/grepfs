#include <u.h>
#include <libc.h>
#include <fcall.h>
#include <thread.h>
#include <9p.h>

/*
 * To start:
 * 	aux/listen1 tcp!*!1234 grepfs /path/to/dir/*
 * The '*' is now important.
 *
 * Searching:
 * 	echo 'ron' > grepctl
 * 	cat grepctl
 * 
 * Changing the grep flags (initially it is grep -n)
 * 	echo 'flags ni' > grepctl
 * 	echo 'subject' > grepctl
 * 	cat grepctl (will return Subject and subject)
 * Clear all grep flags:
 * 	echo 'flags' > grepctl
 *
 */

int logfd;
int dbg;

char Enoent[] = "Not found";
char Eperm[] = "Permission denied";
char flagstr[] = "flags";
char grepname[] = "grepctl";

enum
{
	Qroot = 0,
	Qgrep,
	Waiting = 0,
	Responding,
};

char	*grepuser, *grepflags, **grepargs;
int	grepstate, greppid, nfiles;
ulong	starttime, grepatime, grepmtime, grepvers;
uvlong	grepoffset;
int 	grepout[2];

void
fsattach(Req *r)
{
	if(grepuser == nil)
		grepuser = estrdup9p(r->ifcall.uname);
	r->fid->qid = (Qid){Qroot, 0, QTDIR};
	r->ofcall.qid = r->fid->qid;
	respond(r, nil);
}

char*
fswalk1(Fid *fid, char *name, Qid *qid)
{
	if(fid->qid.path != Qroot)
		return Enoent;
	if(strcmp(name, grepname) == 0){
		*qid = (Qid){Qgrep, grepvers, QTFILE};
		return nil;
	}
	return Enoent;
}

void
fsopen(Req *r)
{
	switch(r->ifcall.mode & 3){
	case OREAD:
		break;
	case OWRITE:			
		if(r->ofcall.qid.path == Qroot)
			goto Perm;
		break;
	case ORDWR:
	case OEXEC:
		goto Perm;
		break;
	}
	respond(r, nil);
	return;
Perm:
	respond(r, Eperm);
}

int
fill(Dir *dir, int path)
{
	ulong mode;

	if(grepstate == Waiting)
		mode = 0200;
	else
		mode = 0400;
	switch(path){
	case Qroot:
		dir->qid = (Qid){Qroot, 0, QTDIR};
		dir->mode = 0755 | DMDIR;
		dir->atime = starttime;
		dir->mtime = starttime;
		dir->name = estrdup9p("/");
		break;
	case Qgrep:
		dir->qid = (Qid){Qgrep, grepvers, QTFILE};
		dir->mode = mode;
		dir->atime = grepatime;
		dir->mtime = grepmtime;
		dir->name = estrdup9p(grepname);
		break;
	default:
		return -1;
	}
	dir->uid = estrdup9p(grepuser);
	dir->gid = estrdup9p("glenda");
	dir->muid = estrdup9p("ron");
	return 0;
}

int
fsdirgen(int n, Dir *dir, void*)
{
	if(n == 0){
		fill(dir, Qgrep);
		return 0;
	}
	return -1;
}

int
grepread(Req *r, char *err, int esize)
{
	int n;

	if(r->ifcall.offset != grepoffset){
		strecpy(err, err+esize, "No seeking");
		return -1;
	}
	n = read(grepout[0], r->ofcall.data, r->ifcall.count);
	r->ofcall.count = n;
	grepoffset += n;
	return n;
}

void
fsread(Req *r)
{
	int n;
	char err[128];

	switch((int)r->fid->qid.path){
	case Qroot:
		dirread9p(r, fsdirgen, nil);
		respond(r, nil);
		break;
	case Qgrep:
		if(grepstate == Waiting)
			respond(r, "Waiting for query");
		else{
			if((n = grepread(r, err, sizeof(err))) == -1)
				respond(r, err);
			else
				respond(r, nil);
			if(n <= 0){
				close(grepout[0]);
				if(waitpid() != greppid)
					exits("Pid was wrong");
				greppid = 0;
				grepstate = Waiting;
				grepatime = time(nil);
				grepvers++;
			}
		}
		break;
	}
}

void
dogrep(Req *r)
{
	char grepstr[1024], *regx;
	int regxlen;

	regx = r->ifcall.data;
	regxlen = r->ifcall.count;
	if(regx[regxlen - 1] == '\n')
		regxlen--;
        if(regxlen > 1024){
		respond(r , "Regex too long");
		return;
	}
	grepoffset = 0;
	pipe(grepout);
	greppid = fork();
	if(greppid == -1)
		exits("Fork failed");
	if(greppid == 0){
		close(grepout[0]);
		dup(grepout[1], 1);
		dup(grepout[1], 2);
		close(grepout[1]);
		snprint(grepstr, sizeof(grepstr), "%.*s", regxlen, regx);
		grepargs[1] = grepflags;
		grepargs[2] = grepstr;
		exec("/bin/grep", grepargs);
		exits("Exec failed");
	}
	close(grepout[1]);
	grepstate = Responding;
	grepmtime = time(nil);
	grepvers++;
	respond(r, nil);
}

void
doflags(Req *r)
{
	char *flags;
	int flagcount;

	flags = r->ifcall.data + sizeof(flagstr);
	flagcount = r->ifcall.count - sizeof(flagstr);
	if(flags[flagcount - 1] == '\n')
		flagcount--;
	if(flagcount > 10){
		respond(r, "Too many flags");
		return;
	}
	free(grepflags);
	if(flagcount <= 0)
		grepflags = estrdup9p("--");
	else
		grepflags = smprint("-%.*s", flagcount, flags);
	if(grepflags == nil)
		exits("Could not set grepflags");
	respond(r, nil);
}
	
void
fswrite(Req *r)
{
	switch((int)r->fid->qid.path){
	case Qroot:
		respond(r, Eperm);
		break;
	case Qgrep:
		if(grepstate == Responding)
			respond(r, "Query in progress");
		else{
			if(strncmp(r->ifcall.data, flagstr, sizeof(flagstr)-1) == 0)
				doflags(r);
			else
				dogrep(r);
		}
		break;
	}
}

void
fsstat(Req *r)
{
	if(fill(&r->d, r->fid->qid.path) == -1)
		respond(r, "No such file");
	else
		respond(r, nil);
}

Srv fs = {
	.attach = 	fsattach,
	.walk1 =	fswalk1,
	.open =		fsopen,
	.read =		fsread,
	.write =	fswrite,
	.stat =		fsstat
};

void
main(int argc, char **argv)
{
	int i;

	ARGBEGIN{
	case 'D':
		dbg++;
		break;
	case 'c':
		chatty9p++;
		break;
	default:
		fprint(2, "Usage: grepfs /path/to/files/*\n");
		exits("usage");
		break;
	}ARGEND

	if(argc < 1){
		fprint(2, "Usage: grepfs /path/to/files/*\n");
		exits("usage");
	}
	grepargs = emalloc9p(sizeof(*grepargs) * (argc + 4));
	*grepargs = "grep";
	for(i = 0; i < argc; i++)
		grepargs[i+3] = argv[i];
	grepargs[i+3] = nil;
	grepflags = estrdup9p("-n");
	starttime = grepatime = grepmtime = time(nil);
	if(dbg){
		logfd = create("/tmp/grepfs.log", OWRITE, 0644);
		postmountsrv(&fs, "grepfs", nil, 0);
	}else{
		fs.infd = 0;
		fs.outfd = 1;
		srv(&fs);
	}
	exits(0);
}
