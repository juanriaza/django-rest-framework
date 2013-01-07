"""
Provides a set of pluggable authentication policies.
"""

import os
import base64
import hashlib
from django.contrib.auth import authenticate
from django.utils.encoding import smart_unicode, DjangoUnicodeDecodeError
from rest_framework import exceptions
from rest_framework.compat import User, CsrfViewMiddleware
from rest_framework.authtoken.models import Token


class BaseAuthentication(object):
    """
    All authentication classes should extend BaseAuthentication.
    """

    def authenticate(self, request):
        """
        Authenticate the request and return a two-tuple of (user, token).
        """
        raise NotImplementedError(".authenticate() must be overridden.")


class BasicAuthentication(BaseAuthentication):
    """
    HTTP Basic authentication against username/password.
    """

    def authenticate(self, request):
        """
        Returns a `User` if a correct username and password have been supplied
        using HTTP Basic authentication.  Otherwise returns `None`.
        """
        if 'HTTP_AUTHORIZATION' in request.META:
            auth = request.META['HTTP_AUTHORIZATION'].split()
            if len(auth) == 2 and auth[0].lower() == "basic":
                try:
                    auth_parts = base64.b64decode(auth[1]).partition(':')
                except TypeError:
                    return None

                try:
                    userid = smart_unicode(auth_parts[0])
                    password = smart_unicode(auth_parts[2])
                except DjangoUnicodeDecodeError:
                    return None

                return self.authenticate_credentials(userid, password)

    def authenticate_credentials(self, userid, password):
        """
        Authenticate the userid and password against username and password.
        """
        user = authenticate(username=userid, password=password)
        if user is not None and user.is_active:
            return (user, None)


class SessionAuthentication(BaseAuthentication):
    """
    Use Django's session framework for authentication.
    """

    def authenticate(self, request):
        """
        Returns a `User` if the request session currently has a logged in user.
        Otherwise returns `None`.
        """

        # Get the underlying HttpRequest object
        http_request = request._request
        user = getattr(http_request, 'user', None)

        # Unauthenticated, CSRF validation not required
        if not user or not user.is_active:
            return

        # Enforce CSRF validation for session based authentication.
        class CSRFCheck(CsrfViewMiddleware):
            def _reject(self, request, reason):
                # Return the failure reason instead of an HttpResponse
                return reason

        reason = CSRFCheck().process_view(http_request, None, (), {})
        if reason:
            # CSRF failed, bail with explicit error message
            raise exceptions.PermissionDenied('CSRF Failed: %s' % reason)

        # CSRF passed with authenticated user
        return (user, None)


class TokenAuthentication(BaseAuthentication):
    """
    Simple token based authentication.

    Clients should authenticate by passing the token key in the "Authorization"
    HTTP header, prepended with the string "Token ".  For example:

        Authorization: Token 401f7ac837da42b97f613d789819ff93537bee6a
    """

    model = Token
    """
    A custom token model may be used, but must have the following properties.

    * key -- The string identifying the token
    * user -- The user to which the token belongs
    """

    def authenticate(self, request):
        auth = request.META.get('HTTP_AUTHORIZATION', '').split()

        if len(auth) == 2 and auth[0].lower() == "token":
            key = auth[1]
            try:
                token = self.model.objects.get(key=key)
            except self.model.DoesNotExist:
                return None

            if token.user.is_active:
                return (token.user, token)


class DigestAuthentication(BaseAuthentication):
    """
    HTTP Digest authentication against username/password.
    Compliant with RFC 2617 (http://tools.ietf.org/html/rfc2617).

    Based on
    # http://flask.pocoo.org/snippets/31/
    # https://github.com/shanewholloway/werkzeug/blob/master/werkzeug/contrib/authdigest.py
    # https://github.com/kennethreitz/httpbin/blob/master/httpbin/core.py#L292
    # https://github.com/Almad/django-http-digest
    """
    model = User
    username_field = 'username'
    password_field= 'password'
    realm = 'django-rest-framework'
    hash_algorithms = {
        'MD5': hashlib.md5,
        'SHA': hashlib.sha1}
    algorithm = 'MD5' # 'MD5' or 'SHA'
    # quality of protection
    qop = 'auth' # 'auth' or 'auth-int'

    def authenticate(self, request):
        """
        Returns a `User` if a correct username and password have been supplied
        using HTTP Digest authentication.  Otherwise returns `None`.
        """
        if 'HTTP_AUTHORIZATION' in request.META:
            # TODO: choose one of the implementations
            self.parse_authorization_header_1(request.META['HTTP_AUTHORIZATION'])
            # auth_header = self.parse_authorization_header_2(request.META['HTTP_AUTHORIZATION'])
            self.check_authorization_header()

            if self.check_digest_auth(request):
                print 'YAY'

    def authenticate_header(self, request):
        """
        Builds the WWW-Authenticate response header

        status_code = 401

        Reference:
            http://pretty-rfc.herokuapp.com/RFC2617#specification.of.digest.headers
        """
        # TODO: choose one of the implementations
        nonce_data = '%s:%s' % (self.realm, os.urandom(8))
        # nonce_data = '%s:%s:%s' % (request.remote_addr, time.time(), os.urandom(10)))
        nonce = self.hash_func(nonce_data)
        opaque = getattr(self, 'opaque', os.urandom(10))

        # TODO: check stale flag
        # A flag, indicating that the previous request from
        # the client was rejected because the nonce value was stale.

        header_format = 'Digest realm="%(realm)s", qop="%(qop)s", nonce="%(nonce)s", opaque="%(opaque)s"'
        header_values = {
            'realm' : self.realm,
            'qop' : self.qop,
            'algorithm': self.algorithm,
            'nonce' : nonce,
            'opaque': opaque}
        header = header_format % header_values
        return header

    def parse_authorization_header_1(self, auth_header):
        if not auth_header.startswith('Digest '):
            raise exceptions.ParseError('Header do not start with Digest')
        auth_header = auth_header.replace('Digest ', '')
        from requests.utils import parse_dict_header
        # we can add parse_dict_header to the utils module
        self.auth_header = parse_dict_header(auth_header)

    def parse_authorization_header_2(self, auth_header):
        if not auth_header.startswith('Digest '):
            raise exceptions.ParseError('Header do not start with Digest')
        auth_header = auth_header.replace('Digest ', '')
        import urllib2
        items = urllib2.parse_http_list(auth_header)
        params = urllib2.parse_keqv_list(items)
        self.auth_header = params

    def check_authorization_header(self):
        # {'username': 'user', 'nonce': 'ea3a64f36d094ab560c29e3e8d7ed320', 'nc': '00000001', 'realm': 'me@kennethreitz.com',
        # 'opaque': '5fe36b905943e32dd5566c9797946e1c', 'cnonce': '997b2506f8a838b2', 'qop': 'auth',
        # 'uri': '/digest-auth/auth/user/pass','response': '1cd62b7a35d5fdad7291e6789107cb1c'}

        # The values of the opaque and algorithm fields must be those supplied in the WWW-Authenticate response header
        if 'opaque' in self.auth_header:
            opaque = getattr(self, 'opaque')
            if opaque:
                if not self.auth_header['opaque'] == opaque:
                    raise exceptions.ParseError('Opaque provided not valid')
        if 'algorithm' in self.auth_header:
            if not self.auth_header['algorithm'] == self.algorithm:
                raise exceptions.ParseError('Algorithm provided not valid')

        required = (
            # The user's name in the specified realm.
            'username',
            'realm',
            'nonce',
            'uri',
            # A string of 32 hex digits computed as defined below, which proves that the user knows a password
            'response')

        for field in required:
            if field not in self.auth_header:
                raise exceptions.ParseError('Required field %s not found' % field)

        if not self.auth_header['realm'] == self.realm:
            raise exceptions.ParseError('Provided realm not valid')

        if 'qop' in self.auth_header:
            if self.auth_header['qop'] not in ('auth', 'auth-int'):
                self.auth_header['qop'] = None
            else:
                # check for qop companions
                raise exceptions.ParseError('qop sent without cnonce and cn')

    def check_digest_auth(self, request):
        """
        Check user authentication using HTTP Digest auth
        """
        response_hash = self.generate_response(request)
        return response_hash == self.auth_header['response']

    def generate_response(self, request):
        """
        Compile digest auth response

        If the qop directive's value is "auth" or "auth-int" , then compute the response as follows:
           RESPONSE = MD5(HA1:nonce:nonceCount:clienNonce:qop:HA2)
        Else if the qop directive is unspecified, then compute the response as follows:
           RESPONSE = MD5(HA1:nonce:HA2)
        """
        password = 'JAJA'
        HA1_value = self.HA1(password)
        HA2_value = self.HA2(request)

    def HA1(self, password):
        """
        Create HA1 hash by realm, username, password

        HA1 = md5(A1) = MD5(username:realm:password)
        """
        A1 = '%s:%s:%s' % (self.auth_header['username'], self.realm, password)
        return self.hash_func(A1)

    def HA2(self, request):
        """
        Create HA2 md5 hash

        If the qop directive's value is "auth" or is unspecified, then HA2:
            HA2 = md5(A2) = MD5(method:digestURI)
        If the qop directive's value is "auth-int", then HA2 is
            HA2 = md5(A2) = MD5(method:digestURI:MD5(entityBody))
        """
        request_method = request.method
        request_path = request.get_full_path()

        if self.auth_header.get('qop') in ('auth', None):
            A2 = '%s:%s' % (request_method, request_path)
            return self.hash_func(A2)
        elif self.auth_header.get('qop') == 'auth-int':
            request_body = request.body
            body_hash = self.hash_func(request_body)
            A2 = '%s:%s:%s' % (request_method,
                    request_path,
                    body_hash)
            return self.hash_func(A2)


    def hash_func(self, data):
        alg_hash_func = self.hash_algorithms[self.algorithm]
        return alg_hash_func(data).hexdigest()


# TODO: OAuthAuthentication
