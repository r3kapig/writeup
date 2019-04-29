
## Features

- 2-3x faster than the [node-glob](https://github.com/isaacs/node-glob) module, with the same glob syntax
- generic: supports multiple glob engines, allowing you to use the fastest glob engine available and compare performance between glob engines
  - currently works with wildmatch, minimatch and globy
- supports multiple glob expressions for each search
- supports exclude/negative glob expressions
- supports filtering out duplicates
- supports streaming (can return a duplex stream, where the glob results are returned from the stream, and any values written to the stream are passed through)

### Benchmarks

Tested:

- [isaacs/node-glob](https://github.com/isaacs/node-glob)
- [isaacs/minimatch](https://github.com/isaacs/minimatch)
- [vmeurisse/wildmatch](https://github.com/vmeurisse/wildmatch)
- [norahiko/globy](https://github.com/norahiko/globy); looks interesting but comes with a native binding which seems a bit too much, fnmatch is undocumented but benchmarked here anyway.

I also had a look at [kthompson/glob-js](https://github.com/kthompson/glob-js) and [fitzgen/glob-to-regexp](https://github.com/fitzgen/glob-to-regexp/) but they were missing key features such as globstar support and relative glob support and so I could not benchmark them. Most other glob modules on npm are just wrappers over minimatch or node-glob.

The following numbers are from a VM running on a Macbook Pro:

<table>
  <tr>
    <td></td>
    <td>100k files, `**/*.txt`</td>
  </tr>
  <tr>
    <td>`/bin/bash`</td>
    <td>1.244s</td>
  </tr>
  <tr>
    <td>node `statSync` + `readdirSync`</td>
    <td>2.748s</td>
  </tr>
  <tr>
    <td>wildglob sync (minimatch)</td>
    <td>5.532s</td>
  </tr>
  <tr>
    <td>wildglob async (minimatch)</td>
    <td>12.287s</td>
  </tr>
  <tr>
    <td>isaacs/node-glob sync</td>
    <td>13.418s</td>
  </tr>
  <tr>
    <td>isaacs/node-glob async</td>
    <td>1m0.365s</td>
  </tr>
</table>

When run with a no-op matcher (e.g. a useless but fast function that returns true for every item), wildglob ran in 3.490s. From this we can conclude:

- that the `.sync()` calls which use synchronous I/O are faster than the `.async()` calls
- that `wildglob` has an overhead of ~800ms over just using `fs` operations
- that adding a matcher algorithm such as minimatch adds another 2000ms or so; in `wildglob` the majority of the runtime is spent on the matching itself
- that interestingly, minimatch itself is quite fast, faster than wildmatch and the slowness in node-glob is mostly from management overhead rather than the matching engine itself (which definitely surprised me)

# API

`glob(patterns, [opts], onDone)`

`glob.sync(patterns, [opts])`

`glob.stream(pattern, opts)`

- `patterns`: a single glob string, or an array of glob expressions. To exclude items, start the glob with `!` to negate the match.
- `opts.cwd`: The working directory; defaults to `process.cwd()`. All glob expressions which refer to a relative path e.g `*/**.js` or `./foo/*` are resolved in the working directory.
- `opts.root`: When glob expressions refer to an absolute path e.g. `/foo/*`, resolve them as if the initial `/` was replaced with `opts.root`. Basically allows you to pretend that the fs root is somewhere else. Defaults to `/`.
- `opts.match`: a function with the following signature `function(filepath, glob)`. Called for each file to perform an exact glob match; should return true if the glob pattern matches.
- `opts.abspath`: normally, relative globs return relative paths and absolute globs return absolute paths. Setting `abspath` to true will cause all paths returned from `wildglob` to be full absolute paths.
- `opts.fs`: allows substituting `fs` with a different object.

## Algorithm

A glob expression is an expression which can potentially match against any path in the file system. For example `/foo/**` basically says take the whole file system and compare it against that expression, and return the result.

However, stat'ing the whole file system is obviously inefficient, since we can use the glob expression itself to narrow down the potential matches:

- first, we can parse the path prefix. This is done as follows:
  - tokenize the glob using `glob-parse`
  - take the prefix which consists of strings and brace expansion expressions. If you encounter an item which is not a string and not a brace expression (e.g. is a `?`, a `*`, a globstar (`**`), a set (`[]`) or a extglob (`@()`)), stop adding things to the prefix.
  - expand the brace expansion expressions to produce an array of paths
- next, start a directory traversal for each path.
- (TODO): apply exclude globs (up to their constant portion, including exclude globs with a globstar as the last item)
- once you have read the results, check against the include globs, then the any exclude globs.

`wildglob` takes the position that perfectly processing globstars and other wildcard expressions is probably more trouble than it is worth, since these expressions will generally not exclude any additional directories (which is the only way to reduce fs operations and provide a potential speedup). As you can see in the benchmark, this works out OK compared to Minimatch which does a more exact but more CPU-intensive matching before looking at the file system.

`wildglob` may perform some additional directory reads, but only if your file tree is such that only a very small portion of the files are included and you have not used exclude expressions to prune the search. If the majority of the files are included, then very little additional work takes place - often none at all, if all directories needed to be `readdir`'ed anyway. For example, if your include expression ends in the a globstar (as is typical), then this is the optimal behavior.

When the directory traversal starts, each include glob has been expanded so that only "tricky" parts remains. Matching a `?`, `*`, a globstar or a extglob is rather tricky - typically, glob implementations use backtracking to deal with wildcard expressions such as these expressions. This results in a fairly high branching factor particularly for globstars.

### Further performance improvements

An optimal implementation should use a minimum amount of CPU time and also avoid recursing into directories which will never produce matches. The latter part relies on the fixed portions of the glob expression having appropriate matches, which has diminishing returns once the prefix has been processed. Exclusions which will only exclude files will probably only have small returns, while excluding large folders early on can have a larger impact.

Here are a couple of ideas:

- rel-to-absglob: convert a relative glob into an absolute glob expression (mainly avoids the hassles with converting back and forth on mixed glob expressions as abspaths are what the fs API uses)
- also makes exclude prefix matching easy
- globstack:
  - include, exclude, include, exclude =>
    - Include mode:
      - ieie
      - ie
    - Exclude prefix mode:
      - eie
      - e
- adding set expansion support (only improves performance for globs with sets)
- adding expansion support for extglob contents (only improves performance for globs with extglob expressions)
- performing full matching before traversing into a subdirectory ([matched](https://github.com/jonschlinkert/matched) has a nice description of why you would want to do this)
  - on exclude expressions only consisting of strings and braces
  - on exclude expressions ending in a globstar
- performing partial matching before traversing into a subdirectory
  - on include expressions (only where you can be certain that partial failure to match === complete failure to match => safe to exclude)
  - on exclude expressions (only where you can be certain that partial success === complete success => safe to exclude)
- speeding up the actual glob matching: specifically, using a finite state machine to perform the matching

## Misc

Other glob implementations:

- [git glob](https://github.com/git/git/blob/master/wildmatch.c)
- [Go glob](http://golang.org/src/pkg/path/filepath/match.go?s=5450:5505#L221)
- [Python glob](http://hg.python.org/cpython/file/2.7/Lib/fnmatch.py)
- [Java nio glob](http://grepcode.com/file/repository.grepcode.com/java/root/jdk/openjdk/7-b147/sun/nio/fs/Globs.java), [[2](https://github.com/rtyley/globs-for-java/blob/master/src/main/java/com/madgag/globs/openjdk/Globs.java)]
- [bash glob](http://git.savannah.gnu.org/cgit/bash.git/tree/lib/glob/glob.c)
- [BSD fnmatch](http://web.mit.edu/freebsd/csup/fnmatch.c)
