module.exports = function(patterns, match) {
  var isInclude = patterns.map(function(pattern) {
      return pattern[0] === '!';
    }),
    // make negated patterns return true when their glob expression matches
    // because it's nicer to think about "include" patterns (+ => +) and
    // "exclude" patterns (+ => -)
    normalizedPatterns = patterns.map(function(pattern, i) {
      return (isInclude ? pattern : pattern.slice(1));
    });

  return function(filepath) {
    var keep = false,
        i;

    for (i = 0; i < normalizedPatterns.length; i++) {
      // the decision to include or exclude a path is only
      // affected by includes matching or excludes matching
      if (match(filepath, normalizedPatterns[i])) {
        keep = isInclude[i]; // include patterns cause inclusion, exclude patterns cause exclusion
      }
    }
    return keep;
  };
};
