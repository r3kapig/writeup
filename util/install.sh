#!/bin/bash

cd markdown-to-html
# Install Markdown to static HTML generator (https://github.com/mixu/markdown-styles)
npm install markdown-styles
# Install customized layout
cp -r r3kapig node_modules/markdown-styles/layouts/

