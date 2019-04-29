// adds _stat and _readdir methods, taking the `sync` and `fs` options into account
module.exports = {
  sync: function(fs) {
    return {
      stat: function statSync(p, onDone) {
        var stat, err;
        try {
          stat = fs.statSync(p);
        } catch (e) {
          err = e;
        }
        onDone(err, stat);
      },
      readdir: function readdirSync(p, onDone) {
        var entries, err;
        try {
          entries = fs.readdirSync(p);
        } catch (e) {
          err = e;
        }
        onDone(err, entries);
      }
    };
  },
  async: function(fs) {
    return {
      stat: fs.stat.bind(fs),
      readdir: fs.readdir.bind(fs)
    };
  }
};
