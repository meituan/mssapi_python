#!/usr/bin/env python

import test_util

conn = test_util.get_conn()

#test create_bucket
conn.create_bucket('test_bucket_0')
conn.create_bucket('test_bucket_1')
conn.create_bucket('test_bucket_2')

#test get_all_buckets
bs = conn.get_all_buckets()
i = 0
for b in bs:
    if b.name.startswith('test_bucket_'):
        test_util.assert_eq( b.name, 'test_bucket_'+str(i), 'test create_bucket '+str(i) )
        i = i+1

test_util.assert_eq( i, 3, 'test get_all_buckets' )

#test get_bucket
b1 = conn.get_bucket('test_bucket_1')
test_util.assert_eq( b1.name, 'test_bucket_1', 'test get_bucket' )

#test delete_bucket
conn.delete_bucket(b1)
b1 = conn.lookup('test_bucket_1')
test_util.assert_eq( None, b1, 'test delete_bucket' )

#test head_bucket
try:
    conn.head_bucket('test_bucket_1')
except Exception as e:
    test_util.assert_true(True, 'test head_bucket')

#test get_bucket validate
b2 = conn.get_bucket('test_bucket_2', validate=False)
try:
    conn.delete_bucket(b2)
except Exception as e:
    test_util.assert_true(False, 'test get_bucket validate')
else:
    test_util.assert_true(True, 'test get_bucket validate')

#test bucket in
res =  'test_bucket_2' in conn
test_util.assert_false(res, 'test bucket in')

test_util.clean_bucket(conn, 'test_bucket_0')
