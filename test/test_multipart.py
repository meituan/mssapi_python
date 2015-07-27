#!/usr/bin/env python

import os
import test_util
import hashlib

conn = test_util.get_conn()

fpath = 'multipart'
fps = []
b = conn.create_bucket('test_multipart_bucket')
mp = b.initiate_multipart_upload('multipart_key')

md5 = hashlib.md5()

for i in xrange(0, 4):
    buf = str(i)*5*1024*1024

    fp = open(fpath + str(i), 'w+' )
    fp.write(buf)
    fp.seek(0, 0)
    fps.append(fp)

    md5.update(buf)

for i in xrange(0, 4):
    mp.upload_part_from_file(fps[i], part_num=i + 1)

mp.complete_upload()

for i in xrange(0, 4):
    os.remove(fpath + str(i))

sum = md5.hexdigest()

k = b.get_key('multipart_key')
buf = k.get_contents_as_string()

test_util.assert_eq( sum, hashlib.md5(buf).hexdigest(),  'test multipart')

test_util.clean_bucket(conn, 'test_multipart_bucket')

