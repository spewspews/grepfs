#include <u.h>
#include <libc.h>
#include <fcall.h>
#include <thread.h>
#include <9p.h>

/*
 * To start:
 * 	aux/listen1 tcp!*!1234 grepml /path/to/foo/index /path/to/bar/index [...]
 * 
 * Searching:
 * 	echo foo '^ron.*sucks$' > grepctl
 * 	cat grepctl (returns results from foo index file)
 * 
 * Changing the grep flags (initially it is grep -n)
 * 	echo 'flags ni' > grepctl
 * 	echo 'bar subject' > grepctl
 * 	cat grepctl (will return Subject and subject from bar index file)
 * Clear all grep flags:
 * 	echo 'flags' > grepctl
 */

typedef struct Ftab Ftab;
struct Ftab
{
	char *name;
	char *path;
};

enum
{
	Qroot = 0,
	Qgrep,
	Waiting = 0,
	Responding,
	Closeme
};

int logfd;
int dbg;

char Enoent[] = "Not found";
char Eperm[] = "Permission denied";
char flagstr[] = "flags";
char grepname[] = "grepctl";

Ftab	*ftab;
char	*grepuser, *grepflags, **grepargs, *allmlstr;
int	grepstate, greppid, ftabn, grepout[2];
ulong	starttime, grepatime, grepmtime, grepvers;
uvlong	grepoffset;

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
	case OWRITE:			
		if(r->ofcall.qid.path == Qroot)
			goto Perm;
		break;
	case ORDWR:
	case OEXEC:
		goto Perm;
		break;
	default:
		break;
	}
	respond(r, nil);
	return;
Perm:
	respond(r, Eperm);
}

void
closegrep(void)
{
	close(grepout[0]);
	if(waitpid() != greppid)
		exits("Pid was wrong");
	greppid = 0;
	grepstate = Waiting;
	grepatime = time(nil);
	grepvers++;
}

void
fsdestroyfid(Fid *f)
{
	if(f->qid.path == Qgrep && grepstate == Closeme)
		closegrep();
}
		
int
fill(Dir *dir, int path)
{
	ulong mode;

	if(grepstate == Waiting)
		mode = 0600;
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
		if(grepstate == Waiting){
			readstr(r, allmlstr);
			respond(r, nil);
			return;
		}
		if(grepstate == Responding)
			grepstate = Closeme;
		if((n = grepread(r, err, sizeof(err))) == -1)
			respond(r, err);
		else
			respond(r, nil);
		if(n <= 0)
			closegrep();
		break;
	}
}

void
dogrep(Req *r)
{
	Ftab *ft;
	char *fname, *regx, errstr[ERRMAX];
	long reqc;

	fname = r->ifcall.data;
	reqc = r->ifcall.count;
	if(fname[reqc - 1] == '\n')
		reqc--;
	fname[reqc - 1] = '\0';
	regx = utfrune(fname, ' ');
	if(regx == nil){
		respond(r, "Bad request");
		return;
	}
	*regx++ = '\0';
	if(strlen(regx) > 1024){
		respond(r , "Regex too long");
		return;
	}
	for(ft = ftab; ft < ftab + ftabn; ft++){
		if(strcmp(fname, ft->name) == 0)
			goto Cont;
	}
	snprint(errstr, ERRMAX, "No such mailing list '%s'", fname);
	respond(r, errstr);
	return;
Cont:
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
		grepargs[1] = grepflags;
		grepargs[2] = regx;
		grepargs[3] = ft->path;
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
			r->ofcall.count = r->ifcall.count;
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
	.destroyfid =	fsdestroyfid,
	.open =		fsopen,
	.read =		fsread,
	.write =	fswrite,
	.stat =		fsstat
};

void
procargs(int nfiles, char **files)
{
	Ftab *ft;
	char **f, *pr;
	char mlheader[] = "Mailing lists:\n";
	long l;

	if(nfiles == 0){
		fprint(2, "No index files provided");
		exits("usage");
	}
	ftab = emalloc9p(sizeof(*ftab) * nfiles);
	ftabn = nfiles;
	l = sizeof(mlheader) - 1;
	for(f = files, ft = ftab; f < files+nfiles; f++, ft++){
		ft->path = estrdup9p(*f);
		pr = utfrrune(*f, '/');
		if(pr)
			*pr = '\0';
		else
			fprint(2, "Bad index file path: %s\n", ft->path);
		pr = utfrrune(*f, '/');
		if(pr)
			ft->name = estrdup9p(pr+1);
		else
			ft->name = estrdup9p(*f);
		l += strlen(ft->name) + 1;
	}
	l++;
	allmlstr = emalloc9p(l);
	pr = allmlstr;
	pr = strecpy(pr, allmlstr+l, mlheader);
	for(ft = ftab; ft < ftab+ftabn; ft++){
		pr = strecpy(pr, allmlstr+l, ft->name);
		*pr++ = '\n';
	}
	*pr = '\0';
	grepargs = emalloc9p(sizeof(*grepargs) * 5);
	grepflags = estrdup9p("--");
	grepargs[0] = "grep";
	grepargs[4] = nil;
}

void
main(int argc, char **argv)
{
	ARGBEGIN{
	case 'D':
		dbg++;
		break;
	case 'c':
		chatty9p++;
		break;
	default:
		fprint(2, "Usage: grepml [index files]\n");
		exits("usage");
		break;
	}ARGEND

	if(argc < 1){
		fprint(2, "Usage: grepml [index files]\n");
		exits("usage");
	}
	if(dbg)
		logfd = create("/tmp/grepml.log", OWRITE, 0644);
	procargs(argc, argv);
	starttime = grepatime = grepmtime = time(nil);
	if(dbg)
		postmountsrv(&fs, "grepml", nil, 0);
	else{
		fs.infd = 0;
		fs.outfd = 1;
		srv(&fs);
	}
	exits(0);
}
