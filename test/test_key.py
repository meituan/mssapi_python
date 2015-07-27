#!/usr/bin/env python

import test_util
import os
import hashlib
import httplib

import mssapi
from mssapi.s3.key import Key

def create_file(fn, cont):
    with open(fn, 'w+') as fp:
        fp.write(cont)

def read_file(fn):
    with open(fn, 'r') as fp:
        return fp.read()

conn = test_util.get_conn()
b = conn.create_bucket('test_bucket_0')

#test set_contents_from_string
k = Key(b, 'key_0')

k.set_contents_from_string('key0 cont0')
cont =  k.get_contents_as_string()
test_util.assert_eq( cont, 'key0 cont0',  'test set_metadata')

k.set_contents_from_string('key0 cont1')
cont =  k.get_contents_as_string()
test_util.assert_eq( cont, 'key0 cont1',  'test set_metadata replace')

#test set_metadata
k.set_metadata('name', 'chen')
k.set_contents_from_string('key0 cont1')
val = k.get_metadata('name')
test_util.assert_eq( val, 'chen', 'test set_metadata' )

#test update_metadata
k.update_metadata( {'name': 'chuang'} )
k.set_contents_from_string('key0 cont2')

val = k.get_metadata('name')
test_util.assert_eq( val, 'chuang', 'test update_metadata' )

#test read
k.open()
cont = k.read()
k.close()
test_util.assert_eq( cont, 'key0 cont2',  'test read')

#test delete
k.delete()
res = k.exists()
test_util.assert_false( res, 'test delete')

#test set_contents_from_file
k = Key(b, 'key_1')
create_file('file_w1', '1'*1024)
with open('file_w1', 'r') as fp:
    k.set_contents_from_file(fp, rewind=True)

cont =  k.get_contents_as_string()
test_util.assert_eq( '1'*1024, cont, 'test set_contents_from_file')

#test md5
md5 = hashlib.md5('1'*1024).hexdigest()
test_util.assert_eq( md5, k.md5,  'test k.md5')

os.remove("file_w1")
k.delete()

#test set_contents_from_filename
k = Key(b, 'key_1')
create_file('file_w2', '2'*1024)
k.set_contents_from_filename('file_w2')

cont =  k.get_contents_as_string()
test_util.assert_eq( cont, '2'*1024,  'test set_contents_from_filename')
os.remove("file_w2")

#test copy
b2 = conn.create_bucket('test_bucket_2')
k2 = k.copy('test_bucket_2', 'key_2')
cont =  k2.get_contents_as_string()
test_util.assert_eq( cont, '2'*1024,  'test copy')

#test exists
res1 = k.exists()
k.delete()
res2 = k.exists()
if res1 == True and res2 == False:
    test_util.assert_true( True, 'test exists')

#test get_contents_to_file
with open('file_r1', 'w+') as fp:
    k2.get_contents_to_file(fp)

cont = read_file('file_r1')
test_util.assert_eq( cont, '2'*1024,  'test get_contents_to_file')
os.remove('file_r1')

k2.get_contents_to_filename('file_r2')
cont = read_file('file_r2')
test_util.assert_eq( cont, '2'*1024,  'test get_contents_to_filename')
os.remove('file_r2')

#test generate_url
url =  k2.generate_url(300)
ip, port, sub_url = test_util.get_ip_port_suburl(url)
response = test_util.request(ip, port, sub_url)
test_util.assert_eq( 200, response.status, 'test generate_url' )

#test encrypt_key
k = Key(b, 'encrypt_key')
k.set_contents_from_string('3'*1024, encrypt_key=True)
cont =  k.get_contents_as_string()
test_util.assert_eq( cont, '3'*1024,  'test encrypt_key')

test_util.clean_bucket(conn, 'test_bucket_0')
test_util.clean_bucket(conn, 'test_bucket_2')
