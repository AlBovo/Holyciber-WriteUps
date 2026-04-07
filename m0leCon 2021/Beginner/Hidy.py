#!/usr/bin/env python3
import re

REGEX = r'<span class="(redacted)">(.)</span>'
REGEX2 = r'\[(\d*?)\]\.remove\(\);'

text = open('redacted.html', 'r').read()
spans = [x[1] for x in re.findall(REGEX, text)]
print('ptm{' + ''.join(spans) + '}')