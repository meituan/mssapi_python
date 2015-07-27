#!/usr/bin/env python

import test_util
import time

conn = test_util.get_conn()
b = conn.create_bucket('test_bucket_0')

#test new_key
k0 = b.new_key('key_0')
k0.set_contents_from_string('hello key0')

k1 = b.new_key('key_1')
k1.set_contents_from_string('hello key1')

#test get_all_keys
keys = b.get_all_keys()
i = 0
for k in keys:
    test_util.assert_eq( k.name, 'key_'+str(i), 'test new_key '+str(i) )
    i = i + 1

test_util.assert_eq( i, 2, 'test get_all_keys' )

#test copy_key
b.copy_key('key_2', 'test_bucket_0', 'key_1')
k2 = b.lookup('key_2')
test_util.assert_neq( k2, None, 'test copy_key' )

#test list
ks =  b.list()
ret = True
i = 0
for k in ks:
    ret = k.name == 'key_%d'%i
    if ret != True:
        break
    i = i + 1

test_util.assert_true( ret, 'test list')

#test list with prefix
b.copy_key('aa/bb/cc/sub_key_0', 'test_bucket_0', 'key_1')
b.copy_key('aa/bb/cc/sub_key_1', 'test_bucket_0', 'key_1')
b.copy_key('aa/bb/dd/sub_key_3', 'test_bucket_0', 'key_1')

i = 0
ks =  b.list(prefix = 'aa/bb/cc')
for k in ks:
    ret = k.name == 'aa/bb/cc/sub_key_%d'%i
    if ret != True:
        break
    i = i + 1

test_util.assert_true( ret, 'test list with prefix aa/bb/cc')

ks =  b.list(prefix = 'aa/bb/dd')
for k in ks:
    test_util.assert_eq( k.name, 'aa/bb/dd/sub_key_3', 'test list with prefix aa/bb/dd' )

#test list with delimiter
ks =  b.list(prefix = 'aa/bb', delimiter = '/')
for k in ks:
    test_util.assert_eq( k.name, 'aa/bb/', 'test list with prefix aa/bb and delimiter /' )

ks =  b.list(prefix = 'aa/bb/', delimiter = '/')
i = 0
for k in ks:
    if i == 0:
        ret = k.name == 'aa/bb/cc/'
    else:
        ret = k.name == 'aa/bb/dd/'

    if ret != True:
        break
    i = i + 1

test_util.assert_true( ret, 'test list with prefix aa/bb/ and delimiter /')

b.delete_key( 'aa/bb/cc/sub_key_0' )
b.delete_key( 'aa/bb/cc/sub_key_1' )
b.delete_key( 'aa/bb/dd/sub_key_3' )

#test get_key
k2 = b.get_key('key_2')
test_util.assert_eq( k2.name, 'key_2', 'test get_key' )

#test key in
res =  'key_1' in b
test_util.assert_true(res, 'test key in')

#test delete_key
b.delete_key('key_0')
k0 = b.lookup('key_0')
test_util.assert_eq( k0, None, 'test delete_key' )

#test generate_url
url =  b.generate_url(3000)
ip, port, sub_url = test_util.get_ip_port_suburl(url)
response = test_util.request(ip, port, sub_url)
test_util.assert_eq( 200, response.status, 'test generate_url' )

#test generate_url expires_in_absolute
curr = time.time()

url =  b.generate_url(curr - 1000, expires_in_absolute=True)
ip, port, sub_url = test_util.get_ip_port_suburl(url)
response = test_util.request(ip, port, sub_url)
test_util.assert_eq( 403, response.status, 'test generate_url expires_in_absolute old_time' )

url =  b.generate_url(curr + 1000, expires_in_absolute=True)
ip, port, sub_url = test_util.get_ip_port_suburl(url)
response = test_util.request(ip, port, sub_url)
test_util.assert_eq( 200, response.status, 'test generate_url expires_in_absolute new_time' )

#test set_canned_acl
b.set_canned_acl('public-read')
acl = b.get_acl()
print acl

#test make_public
b.make_public()
acl = b.get_acl()
print acl

#test make_private
b.make_private()
print b.get_acl()

#test delete
b.delete_key('key_1')
b.delete_key('key_2')
b.delete()
b0 = conn.lookup('test_bucket_0')
test_util.assert_eq( b0, None, 'test delete_bucket' )
