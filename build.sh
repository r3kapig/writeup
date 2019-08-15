#!/bin/bash

DIR_LIST=`ls | grep -P '\d{8}-' --color=none`

echo "Building..."
for DIR in $DIR_LIST
do
    ./util/markdown-to-html/node_modules/markdown-styles/bin/generate-md --layout r3kapig --input $DIR/README.md --output $DIR
    mv $DIR/README.html $DIR/index.html
    ./util/markdown-to-html/gen-sidebar.py $DIR/index.html
    ./util/markdown-toc-generator/gen-toc.py $DIR/index.html
done

# ./util/markdown-toc-generator/gen-toc.py
# last dir will be taken
#echo "Generating Index..."
# mv $DIR/README.html ..
