#include <u.h>
#include <libc.h>
#include <fcall.h>
#include <thread.h>
#include <9p.h>

/*
 * To start:
 * 	aux/listen1 tcp!*!1234 grepfs /path/to/dirname
 *
 * Searching:
 * 	echo -n 'rminnich' > dirnamegrep
 * 	cat dirnamegrep
 * 
 * Changing the grep flags (initially it is grep -n)
 * 	echo -n 'flags ni' > dirnamegrep
 * 	echo -n 'subject' > dirnamegrep
 * 	cat dirnamegrep (will return Subject and subject)
 * Clear all grep flags:
 * 	echo -n 'flags' > dirnamegrep (echo -n 'flags ' also works)
 *
 */

int logfd;
int dbg;

char Enoent[] = "Not found";
char Eperm[] = "Permission denied";
char flagstr[] = "flags";

enum
{
	Qroot = 0,
	Qgrep,
	Waiting = 0,
	Responding,
	STACK = 8192
};

ulong	starttime;
char	*grepuser, *grepname, *grepflags, *dname;
int	grepstate, greppid;
ulong	grepatime, grepmtime, grepvers;
uvlong	grepoffset;
int 	grepout[2], greperr[2];

void
fsattach(Req *r)
{
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
fill(Dir *dir, uvlong path)
{
	ulong mode;

	if(grepstate == Waiting)
		mode = 0200;
	else
		mode = 0400;
	switch(path){
	case Qroot:
		dir->qid = (Qid){Qroot, 0, QTDIR};
		dir->mode = 0755;
		dir->atime = starttime;
		dir->mtime = starttime;
		dir->name = estrdup9p("/");
		dir->uid = estrdup9p(grepuser);
		dir->gid = estrdup9p("glenda");
		dir->muid = estrdup9p("ron");
		break;
	case Qgrep:
		dir->qid = (Qid){Qgrep, grepvers, QTFILE};
		dir->mode = mode;
		dir->atime = grepatime;
		dir->mtime = grepmtime;
		dir->name = estrdup9p(grepname);
		dir->uid = estrdup9p(grepuser);
		dir->gid = estrdup9p("glenda");
		dir->muid = estrdup9p("ron");
		break;
	default:
		return -1;
	}
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
	int o, n;

	if((o = read(greperr[0], err, esize)) > 0){
		while((n = read(greperr[0], err+o, esize-o)) > 0)
			o += n;
		err[o-1] = '\0';
		return -1;
	}
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
	char err[1024];

	switch(r->fid->qid.path){
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
				close(greperr[0]);
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
	char grepstr[1024];

	grepoffset = 0;
	pipe(grepout);
	pipe(greperr);
	greppid = fork();
	if(greppid == -1)
		exits("Fork failed");
	if(greppid == 0){
		close(grepout[0]);
		close(greperr[0]);
		dup(grepout[1], 1);
		dup(greperr[1], 2);
		if(grepflags == nil)
			snprint(grepstr, sizeof(grepstr), "grep '%.*s' *", r->ifcall.count, r->ifcall.data);
		else
			snprint(grepstr, sizeof(grepstr), "grep %s '%.*s' *", grepflags, r->ifcall.count, r->ifcall.data);
		execl("/bin/rc", "rc", "-c", grepstr, nil);
		exits("Exec failed");
	}
	close(grepout[1]);
	close(greperr[1]);
	grepstate = Responding;
	grepmtime = time(nil);
	grepvers++;
}

void
doflags(Req *r)
{
	char *flags;
	int flagcount;

	flags = r->ifcall.data + sizeof(flagstr);
	flagcount = r->ifcall.count - sizeof(flagstr);
	free(grepflags);
	if(dbg)
		fprint(logfd, "flagcount: %d\n", flagcount);
	if(flagcount <= 0)
		grepflags = nil;
	else
		grepflags = smprint("-%.*s", flagcount, flags);
}
	
void
fswrite(Req *r)
{
	switch(r->fid->qid.path){
	case Qroot:
		respond(r, Eperm);
		break;
	case Qgrep:
		if(grepstate == Responding)
			respond(r, "Query in progress");
		else{
			if(strncmp(r->ifcall.data, flagstr, sizeof(flagstr)-1) == 0){
				if(dbg) fprint(logfd, "flags: %.*s", r->ifcall.count, r->ifcall.data);
				doflags(r);
				respond(r, nil);
			}else{
				dogrep(r);
				respond(r, nil);
			}
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
	Dir *dir;
	char *dpath;

	ARGBEGIN{
	case 'd':
		dbg++;
		break;
	case 'c':
		chatty9p++;
		break;
	default:
		exits("usage");
		break;
	}ARGEND

	if(argc != 1){
		fprint(2, "Provide a directory to search\n");
		exits("usage");
	}
	dpath = cleanname(argv[0]);
	dname = utfrrune(dpath, '/');
	if(dname != nil)
		dname++;
	else
		dname = dpath;
	dir = dirstat(dpath);
	if((dir->mode & DMDIR) == 0){
		fprint(2, "Must be a directory, %s\n", argv[0]);
		exits("Not a directory");
	}
	free(dir);
	chdir(dpath);
	grepflags = estrdup9p("-n");
	grepname = smprint("%sgrep", dname);
	starttime = grepatime = grepmtime = time(nil);
	if(dbg)	
		logfd = create("/tmp/grepfs.log", OWRITE, 0644);
	if(dbg)
		postmountsrv(&fs, "grepfs", nil, 0);
	else{
		fs.infd = 0;
		fs.outfd = 1;
		srv(&fs);
	}
	exits(0);
}
