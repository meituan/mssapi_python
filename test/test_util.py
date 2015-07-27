
import sys
import httplib

import mssapi
from mssapi.s3.connection import S3Connection
from mssapi.s3.connection import OrdinaryCallingFormat

host = '192.168.4.242'
port = 6008

access_key = '71454bfd78c349288e9758b7972256dc'
access_secret = '3f2c918ed5fc42e2a6a8f69379834f23'

def get_conn():

    conn = S3Connection(
        aws_access_key_id = access_key,
        aws_secret_access_key = access_secret,
        port = port,
        host = host,
        is_secure=False,
        calling_format=OrdinaryCallingFormat(),
    )

    return conn


def assert_eq( exp, act, test_case = '' ):

    if exp != act:
        print test_case + ' fail,  shoud be equal, Expected: ' + str( exp ) + ' Actual: ' + str( act )
        sys.exit()

    print test_case + ' OK'

def assert_neq( exp, act, test_case = '' ):

    if exp == act:
        print test_case + ' fail,  should be not equal, Expected: ' + str( exp ) + ' Actual: ' + str( act )
        sys.exit()

    print test_case + ' OK'

def assert_true( value, test_case = '' ):

    if value != True:
        print test_case + ' fail, should be true'
        sys.exit()

    print test_case + ' OK'

def assert_false( value, test_case = '' ):

    if value != False:
        print test_case + ' fail, should be false'
        sys.exit()

    print test_case + ' OK'


def clean_bucket(conn, bname):

    b = conn.lookup(bname)
    if b != None:
        keys = b.get_all_keys()
        for k in keys:
            k.delete()

        conn.delete_bucket(b)

    b = conn.lookup(bname)
    if b != None:
        raise Exception('clean bucket %s fail'%bname)

#http://192.168.4.242:6008/bucket_0/?Signature=huTlODMyrv6U64CC0FdoE3anR54%3D&Expires=1431402923&AWSAccessKeyId=71454bfd78c349288e9758b7972256dc
def get_ip_port_suburl(url):
    url = url[ len('http://') : ]

    ip_port, suburl = url.split('/', 1)

    if ':' in ip_port:
        ip, port = ip_port.split(':')
    else:
        ip = ip_port
        port = 80

    suburl = '/' + suburl

    return ip, port, suburl

def request(ip, port, url):
    c = httplib.HTTPConnection(ip, port)
    c.request("GET", url)
    res =  c.getresponse()

    return res


