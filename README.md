# MSS(Meituan Storage Service) SDK for python

This is MSS SDK for python。

## Introduction

### MSS服务介绍
美团云存储服务（Meituan Storage Service, 简称MSS)，是美团云对外提供的云存储服务，其具备高可靠，安全，低成本等特性，并且其API兼容S3。MSS适合存放非结构化的数据，比如图片，视频，文档，备份等。

### MSS基本概念介绍
* MSS的API兼容S3, 其基本概念也和S3相同，主要包括Object, Bucket, Access Key, Secret Key等。

* Object对应一个文件，包括数据和元数据两部分。元数据以key-value的形式构成，它包含一些默认的元数据信息，比如Content-Type, Etag等，用户也可以自定义元数据。

* Bucket是object的容器，每个object都必须包含在一个bucket中。用户可以创建任意多个bucket。

* Access Key和Secret Key: 用户注册MSS时，系统会给用户分配一对Access Key和Secret Key, 用于标识用户，用户在使用API使用MSS服务时，需要使用这两个Key。请在美团云管理控制台查询AccessKey和SecretKey。

### MSS访问域名

```
  mtmss.com
```

## Installation
* 下载MSS SDK for python包后，进入MSS SDK for python目录下，运行"sudo python setup.py install"，即可完成MSS SDK for python的安装。

## Quick Start

### create s3 connection

    import mssapi
    from mssapi.s3.connection import S3Connection
    from mssapi.s3.key import Key

    conn = S3Connection(
        aws_access_key_id = access_key,
        aws_secret_access_key = access_secret,
        port = port,
        host = host,
    )

### handle bucket

#### create bucket
    b0=conn.create_bucket('tmpbucket0')
    b1=conn.create_bucket('tmpbucket1')

#### get buckets
    bs = conn.get_all_buckets()
    for b in bs:
        print b.name

#### get bucket
    b1 = conn.get_bucket('tmpbucket1')

#### delete bucket
    conn.delete_bucket(b1)

#### head bucket
    conn.head_bucket('tmpbucket0')

#### bucket in
    'tmpbucket0' in conn

#### get bucket keys
    keys = b0.get_all_keys()
    for k in keys:
        print k.name

### handle key
    bucket = conn.get_bucket('tmpbucket0')

#### create key
    k0 = bucket.new_key('key0')
    k0.set_contents_from_string('hello key0')

    k1 = Key(bucket, 'key1')
    k1.set_contents_from_filename('file_w1')

#### get key
    k0 = bucket.get_key('key0')
    cont =  k0.get_contents_as_string()

    k1 = Key(bucket, 'key1')
    k1.get_contents_to_filename('file_r1')

#### delete key
    bucket.delete_key('key0')

#### lookup key
    bucket.lookup('key0')

#### tmp url
    k1.generate_url(expires_in = 300)

### handle multipart
    first you need to init chunk_path and chunk_num

    mp = bucket.initiate_multipart_upload('multipartkey')

    for i in xrange(0, chunk_num):
        fp = open(chunk_path + str(i), 'r' )
        mp.upload_part_from_file(fp, part_num=i + 1)

    mp.complete_upload()
