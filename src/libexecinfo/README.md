libexecinfo for musl systems, originally from FreeBSD, with patches
from Alpine linux.

Original README
===============

About
-----
This is a quick-n-dirty BSD licensed clone of backtrace facility found
in the GNU libc, mainly intended for porting linuxish code to BSD
platforms, however it can be used at any platform which has a gcc
compiler.

More information about API can be found here:

http://www.gnu.org/software/libc/manual/html_node/Backtraces.html


Known limitations
-----------------
- Depth of stack trace is limited to 128 levels, which should be enough
  in most cases, the limit can be increased by editing gen.py and
  regenerating stacktraverse.c. The reason for that limitation steams
  from the fact that __builtin_return_address() function takes only
  constant as an argument, while gcc(1) has problems compiling giant
  switch() tables. For example to compile one with 1024 entries gcc(1)
  needs more than 1GB of memory (sic!);

- executable have to be linked using `-Wl,--export-dynamic' option,
  in order for function names to be displayed properly.


Author
------
Author of this junk is Maxim Sobolev <sobomax@FreeBSD.org>. Any feedback,
patches or suggestions are greatly appreciated.

$Id: README,v 1.2 2004/07/19 05:13:42 sobomax Exp $
