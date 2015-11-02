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
};

char	*grepuser, *grepname, *grepflags;
int	grepstate, greppid;
ulong	starttime, grepatime, grepmtime, grepvers;
uvlong	grepoffset;
int 	grepout[2], greperr[2];

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
	char err[128];

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
	char grepstr[1024], *regx;
	int regxlen;

	regx = r->ifcall.data;
	regxlen = r->ifcall.count;
	if(regx[regxlen - 1] == '\n')
		regxlen--;
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
			snprint(grepstr, sizeof(grepstr), "grep '%.*s' *", regxlen, regx);
		else
			snprint(grepstr, sizeof(grepstr), "grep %s '%.*s' *", grepflags, regxlen, regx);
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
	if(flags[flagcount - 1] == '\n')
		flagcount--;
	free(grepflags);
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
				doflags(r);
			}else{
				dogrep(r);
			}
			respond(r, nil);
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
	char *dpath, *dname;

	ARGBEGIN{
	case 'D':
		dbg++;
		break;
	case 'c':
		chatty9p++;
		break;
	default:
		fprint(2, "Usage: grepfs /path/to/dir\n");
		exits("usage");
		break;
	}ARGEND

	if(argc != 1){
		fprint(2, "Usage: grepfs /path/to/dir\n");
		exits("usage");
	}
	dpath = cleanname(argv[0]);
	dname = utfrrune(dpath, '/');
	if(dname != nil)
		dname++;
	else
		dname = dpath;
	dir = dirstat(dpath);
	if(dir == nil || (dir->mode & DMDIR) == 0){
		fprint(2, "Usage: %s must be a directory.\n", argv[0]);
		exits("not a directory");
	}
	free(dir);
	chdir(dpath);
	grepflags = estrdup9p("-n");
	grepname = smprint("%sgrep", dname);
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
