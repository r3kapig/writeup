#!/bin/bash
# Description: Bash golfing build script by stypr
# Maintainer: Harold Kim (root@stypr.com)


if [[ "$OSTYPE" == "darwin"* ]]; then
    DIR_LIST=`ls | grep -Ei '\d{8}-' --color=none | tail -r 65535`
else
    DIR_LIST=`ls | grep -P '\d{8}-' --color=none | tail -r 65535`
fi

# Build writeup
echo "Building Writeups..."
for DIR in $DIR_LIST
do
    # generate markdown
    ./util/markdown-to-html/node_modules/markdown-styles/bin/generate-md --layout r3kapig --input $DIR/README.md --output $DIR
    mv $DIR/README.html $DIR/index.html
    ./util/markdown-to-html/gen-sidebar.py $DIR/index.html
    # do we need this file?
    # ./util/markdown-toc-generator/gen-toc.py $DIR/README.md 2>&1
done

# Update writeup list (README.md)
echo "Updating Writeup list..."
SIDEBAR_START=$(expr `sed -n '/##\ Writeups/=' README.md`)
SIDEBAR_END=$(expr `sed -n '/##\ Questions/=' README.md` - 1)
LAST_LINE=`cat README.md | wc -l`
cat /dev/null > README_patched.md
# Write to patched

sed -n "1,${SIDEBAR_START}p;${SIDEBAR_START}q" README.md >> README_patched.md
for DIR in $DIR_LIST
do
    TITLE=`cat $DIR/index.html | grep -o "<title>[^<]*" | sed -e 's/<[^>]*>//g' | sed 's/..........$//'`
    echo "- [$DIR]($DIR): $TITLE" >> README_patched.md
done
sed -n "${SIDEBAR_END},${LAST_LINE}p;${LAST_LINE}q" README.md >> README_patched.md
mv README_patched.md README.md

# Generate index.html from README.md
echo "Generating Index..."
./util/markdown-to-html/node_modules/markdown-styles/bin/generate-md --layout r3kapig --input README.md --output .
mv README.html index.html
./util/markdown-to-html/gen-sidebar.py index.html index_page

# remove asset bug, remove sidebar
sed -i 's/\.\.\//\.\//g' index.html # just patch the assets
sed -i 's/\.\/\">/\.\.\/\">/g' index.html # keep out the header
SIDEBAR_START=$(expr `sed -n '/\"sidebar\-container\"/=' index.html` - 1)
SIDEBAR_END=$(expr `sed -n '/\"col-10\ py-3\"/=' index.html`)
LAST_LINE=`cat index.html | wc -l`
sed -n "1,${SIDEBAR_START}p;${SIDEBAR_END},${LAST_LINE}p;${LAST_LINE}q" index.html > patched.html
sed -i 's/col-10\ py-3/col-12\ py-3/g' patched.html
mv patched.html index.html
