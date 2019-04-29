var path = require('path');

// utils
function nop() {}
function runTaskImmediately(task) { task(nop); }
function absToRel(str, strip) {
  if (strip.length === 0) {
    return str;
  }

  return (str.substr(0, strip.length) == strip ? str.substr(strip.length + (str.charAt(strip.length) === '/' ? 1 : 0)) : str);
}

// implementation
function traverse(filepath, strip, affix, knownToExist, stat, readdir, exec, doStat, filter, onError, onDone) {
  var self = this;

  // the order between stat and filter does not matter, because we'll need to stat each
  // entry anyway to know if it's a dir, even if it fails the filter check (since the full path
  // can still match even if the current partial does not)
  // if we had accurate partial matching then yes, then filter before stat is slightly better.
  stat(filepath, function(err, stat) {
    var exists,
        isDir = false;
    if (err) {
      switch (err.code) {
        case 'ELOOP':
          // like Minimatch, ignore ELOOP for purposes of existence check but not
          // for the actual stat()ing
          exists = knownToExist;
          break;
        case 'ENOENT':
          // ignore ENOENT (per Node core docs, "fs.exists() is an anachronism
          // and exists only for historical reasons. In particular, checking if a file
          // exists before opening it is an anti-pattern")
          exists = false;
          break;
        default:
          exists = false;
          onError(err);
      }
    } else {
      exists = true;
      isDir = stat.isDirectory();
    }

    // console.log('resolve', filepath, exists, isDir);
    // this where partial matches against a pending traversal would help by pruning the tree
    if (isDir) {
      // try without a trailing slash
      if (!filter(affix + absToRel(filepath, strip))) {
        // needed so that wildmatch treats dirs correctly (in some cases)
        if (filepath.charAt(filepath.length - 1) != '/') {
          filter(affix + absToRel(filepath + '/', strip));
        }
      }
      // if the input is a directory, readdir and process all entries in it
      var basepath = (filepath[filepath.length - 1] !== path.sep ? filepath + path.sep : filepath);
      readdir(basepath, function(err, entries) {
        if (err) {
          // console.log(err);
          switch (err.code) {
            case 'ENOTDIR':
            case 'ENOENT':
            case 'ELOOP':
            case 'ENAMETOOLONG':
            case 'UNKNOWN':
              break;
            default:
              onError(err);
          }
          entries = [];
        }
        entries.forEach(function(f) {
          if (f.charAt(0) === '.') {
            return;
          }
          // queue a stat operation
          // filepath, strip, affix, knownToExist, onDone
          exec(function(done) { doStat(basepath + f, strip, affix, true, done); });
        });
        // tasks have been queued so this entry is done
        onDone();
      });
    } else if (exists) {
      filter(affix + absToRel(filepath, strip));
      // no readdir, so the stat for this entry is done
      onDone();
    }
  });
}

module.exports = traverse;
