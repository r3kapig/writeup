TESTS += test/*.js

test:
	@mocha \
	--ui exports \
	--reporter spec \
	--slow 2000ms \
	--bail \
	$(TESTS)

.PHONY: test

build:
	-mkdir ./dist
	./node_modules/gluejs/bin/gluejs \
	--include ./index.js \
	--include ./node_modules/microee/index.js \
	--no-cache \
	--report \
	--command 'uglifyjs --no-copyright' \
	--global miniq \
	--main index.js \
	--out dist/miniq.js
