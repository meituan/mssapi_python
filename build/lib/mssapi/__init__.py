# Copyright (c) 2006-2012 Mitch Garnaat http://garnaat.org/
# Copyright (c) 2010-2011, Eucalyptus Systems, Inc.
# Copyright (c) 2011, Nexenta Systems Inc.
# Copyright (c) 2012 Amazon.com, Inc. or its affiliates.
# Copyright (c) 2010, Google, Inc.
# All rights reserved.
#
# Permission is hereby granted, free of charge, to any person obtaining a
# copy of this software and associated documentation files (the
# "Software"), to deal in the Software without restriction, including
# without limitation the rights to use, copy, modify, merge, publish, dis-
# tribute, sublicense, and/or sell copies of the Software, and to permit
# persons to whom the Software is furnished to do so, subject to the fol-
# lowing conditions:
#
# The above copyright notice and this permission notice shall be included
# in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
# OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABIL-
# ITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT
# SHALL THE AUTHOR BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
# WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
# IN THE SOFTWARE.
#
from mssapi.pyami.config import Config, MssapiConfigLocations
from mssapi.storage_uri import BucketStorageUri, FileStorageUri
import mssapi.plugin
import datetime
import os
import platform
import re
import sys
import logging
import logging.config

from mssapi.compat import urlparse
from mssapi.exception import InvalidUriError

__version__ = '1.0'
Version = __version__  # for backware compatibility

# http://bugs.python.org/issue7980
datetime.datetime.strptime('', '')

UserAgent = 'Mssapi/%s Python/%s %s/%s' % (
    __version__,
    platform.python_version(),
    platform.system(),
    platform.release()
)
config = Config()

# Regex to disallow buckets violating charset or not [3..255] chars total.
BUCKET_NAME_RE = re.compile(r'^[a-zA-Z0-9][a-zA-Z0-9\._-]{1,253}[a-zA-Z0-9]$')
# Regex to disallow buckets with individual DNS labels longer than 63.
TOO_LONG_DNS_NAME_COMP = re.compile(r'[-_a-z0-9]{64}')
GENERATION_RE = re.compile(r'(?P<versionless_uri_str>.+)'
                           r'#(?P<generation>[0-9]+)$')
VERSION_RE = re.compile('(?P<versionless_uri_str>.+)#(?P<version_id>.+)$')
ENDPOINTS_PATH = os.path.join(os.path.dirname(__file__), 'endpoints.json')


def init_logging():
    for file in MssapiConfigLocations:
        try:
            logging.config.fileConfig(os.path.expanduser(file))
        except:
            pass


class NullHandler(logging.Handler):
    def emit(self, record):
        pass

log = logging.getLogger('mssapi')
perflog = logging.getLogger('mssapi.perf')
log.addHandler(NullHandler())
perflog.addHandler(NullHandler())
init_logging()

# convenience function to set logging to a particular file


def set_file_logger(name, filepath, level=logging.INFO, format_string=None):
    global log
    if not format_string:
        format_string = "%(asctime)s %(name)s [%(levelname)s]:%(message)s"
    logger = logging.getLogger(name)
    logger.setLevel(level)
    fh = logging.FileHandler(filepath)
    fh.setLevel(level)
    formatter = logging.Formatter(format_string)
    fh.setFormatter(formatter)
    logger.addHandler(fh)
    log = logger


def set_stream_logger(name, level=logging.DEBUG, format_string=None):
    global log
    if not format_string:
        format_string = "%(asctime)s %(name)s [%(levelname)s]:%(message)s"
    logger = logging.getLogger(name)
    logger.setLevel(level)
    fh = logging.StreamHandler()
    fh.setLevel(level)
    formatter = logging.Formatter(format_string)
    fh.setFormatter(formatter)
    logger.addHandler(fh)
    log = logger


def connect_s3(aws_access_key_id=None, aws_secret_access_key=None, **kwargs):
    """
    :type aws_access_key_id: string
    :param aws_access_key_id: Your AWS Access Key ID

    :type aws_secret_access_key: string
    :param aws_secret_access_key: Your AWS Secret Access Key

    :rtype: :class:`mssapi.s3.connection.S3Connection`
    :return: A connection to Amazon's S3
    """
    from mssapi.s3.connection import S3Connection
    return S3Connection(aws_access_key_id, aws_secret_access_key, **kwargs)


def storage_uri(uri_str, default_scheme='file', debug=0, validate=True,
                bucket_storage_uri_class=BucketStorageUri,
                suppress_consec_slashes=True, is_latest=False):
    """
    Instantiate a StorageUri from a URI string.

    :type uri_str: string
    :param uri_str: URI naming bucket + optional object.
    :type default_scheme: string
    :param default_scheme: default scheme for scheme-less URIs.
    :type debug: int
    :param debug: debug level to pass in to mssapi connection (range 0..2).
    :type validate: bool
    :param validate: whether to check for bucket name validity.
    :type bucket_storage_uri_class: BucketStorageUri interface.
    :param bucket_storage_uri_class: Allows mocking for unit tests.
    :param suppress_consec_slashes: If provided, controls whether
        consecutive slashes will be suppressed in key paths.
    :type is_latest: bool
    :param is_latest: whether this versioned object represents the
        current version.

    We allow validate to be disabled to allow caller
    to implement bucket-level wildcarding (outside the mssapi library;
    see gsutil).

    :rtype: :class:`mssapi.StorageUri` subclass
    :return: StorageUri subclass for given URI.

    ``uri_str`` must be one of the following formats:

    * gs://bucket/name
    * gs://bucket/name#ver
    * s3://bucket/name
    * gs://bucket
    * s3://bucket
    * filename (which could be a Unix path like /a/b/c or a Windows path like
      C:\a\b\c)

    The last example uses the default scheme ('file', unless overridden).
    """
    version_id = None
    generation = None

    # Manually parse URI components instead of using urlparse because
    # what we're calling URIs don't really fit the standard syntax for URIs
    # (the latter includes an optional host/net location part).
    end_scheme_idx = uri_str.find('://')
    if end_scheme_idx == -1:
        scheme = default_scheme.lower()
        path = uri_str
    else:
        scheme = uri_str[0:end_scheme_idx].lower()
        path = uri_str[end_scheme_idx + 3:]

    if scheme not in ['file', 's3', 'gs']:
        raise InvalidUriError('Unrecognized scheme "%s"' % scheme)
    if scheme == 'file':
        # For file URIs we have no bucket name, and use the complete path
        # (minus 'file://') as the object name.
        is_stream = False
        if path == '-':
            is_stream = True
        return FileStorageUri(path, debug, is_stream)
    else:
        path_parts = path.split('/', 1)
        bucket_name = path_parts[0]
        object_name = ''
        # If validate enabled, ensure the bucket name is valid, to avoid
        # possibly confusing other parts of the code. (For example if we didn't
        # catch bucket names containing ':', when a user tried to connect to
        # the server with that name they might get a confusing error about
        # non-integer port numbers.)
        if (validate and bucket_name and
            (not BUCKET_NAME_RE.match(bucket_name)
             or TOO_LONG_DNS_NAME_COMP.search(bucket_name))):
            raise InvalidUriError('Invalid bucket name in URI "%s"' % uri_str)
        if scheme == 'gs':
            match = GENERATION_RE.search(path)
            if match:
                md = match.groupdict()
                versionless_uri_str = md['versionless_uri_str']
                path_parts = versionless_uri_str.split('/', 1)
                generation = int(md['generation'])
        elif scheme == 's3':
            match = VERSION_RE.search(path)
            if match:
                md = match.groupdict()
                versionless_uri_str = md['versionless_uri_str']
                path_parts = versionless_uri_str.split('/', 1)
                version_id = md['version_id']
        else:
            raise InvalidUriError('Unrecognized scheme "%s"' % scheme)
        if len(path_parts) > 1:
            object_name = path_parts[1]
        return bucket_storage_uri_class(
            scheme, bucket_name, object_name, debug,
            suppress_consec_slashes=suppress_consec_slashes,
            version_id=version_id, generation=generation, is_latest=is_latest)


def storage_uri_for_key(key):
    """Returns a StorageUri for the given key.

    :type key: :class:`mssapi.s3.key.Key` or subclass
    :param key: URI naming bucket + optional object.
    """
    if not isinstance(key, mssapi.s3.key.Key):
        raise InvalidUriError('Requested key (%s) is not a subclass of '
                              'mssapi.s3.key.Key' % str(type(key)))
    prov_name = key.bucket.connection.provider.get_provider_name()
    uri_str = '%s://%s/%s' % (prov_name, key.bucket.name, key.name)
    return storage_uri(uri_str)

mssapi.plugin.load_plugins(config)
