COMPRESS := ./node_modules/.bin/uglifyjs

build:
	@echo ';(function(module) {' > ./dist/microee.temp.js
	@cat index.js >> ./dist/microee.temp.js
	@echo 'microee = module.exports;' >> ./dist/microee.temp.js
	@echo '}({}));' >> ./dist/microee.temp.js
	@echo 'Wrote ./dist/microee.temp.js'
	@ls -lah ./dist/
	@$(COMPRESS) --compress --mangle sort ./dist/microee.temp.js 2> /dev/null > ./dist/microee.js
	@rm ./dist/microee.temp.js
	@echo 'Applied uglifyjs.'
	@ls -lah ./dist/

test:
	@./node_modules/.bin/mocha \
	--ui exports \
	--reporter spec \
	--slow 2000ms \
	--bail \
	test/microee.test.js

.PHONY: build test
