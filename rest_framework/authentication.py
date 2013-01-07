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
                token = User.objects.get(key=key)
            except User.DoesNotExist:
                return None

            if token.user.is_active:
                return (token.user, token)


class DigestAuthentication(BaseAuthentication):
    """
    HTTP Digest authentication against username/password.
    Compliant with RFC 2617 (http://tools.ietf.org/html/rfc2617).
    """
    realm = 'django-rest-framework'
    hash_algorithms = {
        'MD5': hashlib.md5,
        'MD5-sess': hashlib.md5,
        'SHA': hashlib.sha1}
    algorithm = 'MD5' # 'MD5'/'SHA'/'MD5-sess'
    # quality of protection
    qop = 'auth' # 'auth'/'auth-int'/None
    opaque = None

    def authenticate(self, request):
        if not self.opaque:
            self.opaque = os.urandom(10)

        if 'HTTP_AUTHORIZATION' in request.META:
            # TODO: choose one of the implementations
            self.parse_authorization_header_1(request.META['HTTP_AUTHORIZATION'])
            # auth_header = self.parse_authorization_header_2(request.META['HTTP_AUTHORIZATION'])
            self.check_authorization_request_header()

            user = self.get_user()
            password = user.password
            if self.check_digest_auth(request, password):
                return (None, user, None)

    def authenticate_header(self, request):
        """
        Builds the WWW-Authenticate response header
        """
        # TODO: choose one of the implementations
        # http://pretty-rfc.herokuapp.com/RFC2617#the.www-authenticate.response.header
        nonce_data = '%s:%s' % (self.realm, os.urandom(8))
        # nonce_data = '%s:%s:%s' % (request.META.get('REMOTE_ADDR'), time.time(), os.urandom(10)))
        # nonce_data = "%s:%s" % (time.time(), self.realm)
        nonce = self.hash_func(nonce_data)

        # TODO: check stale flag
        # A flag, indicating that the previous request from
        # the client was rejected because the nonce value was stale.

        header_format = 'Digest realm="%(realm)s", qop="%(qop)s", nonce="%(nonce)s", opaque="%(opaque)s"'
        header_values = {
            'realm' : self.realm,
            'qop' : self.qop,
            'algorithm': self.algorithm,
            'opaque': self.opaque,
            'nonce' : nonce}
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

    def check_authorization_request_header(self):
        """
        The values of the opaque and algorithm fields must be those supplied
        in the WWW-Authenticate response header
        """
        required_fields = ('username', 'realm', 'nonce', 'uri',
                           'response','algorithm', 'opaque')

        for field in required_fields:
            if field not in self.auth_header:
                raise exceptions.ParseError('Required field %s not found' % field)

        for field in ('opaque', 'algorithm', 'realm', 'qop'):
            if not self.auth_header[field] == getattr(self, field):
                raise exceptions.ParseError('%s provided not valid' % field)

        qop = self.auth_header.get('qop')
        if qop in ('auth', 'auth-int'):
            for c in ('nc', 'cnonce'):
                if c not in self.auth_header:
                    raise exceptions.ParseError('%s is required' % c)
        if not qop:
            for c in ('nc', 'cnonce'):
                if c in self.auth_header:
                    raise exceptions.ParseError('%s provided without qop' % c)

    def get_user(self):
        username = self.auth_header['username']
        try:
            user = User.objects.get(username=username)
        except User.DoesNotExist:
            raise exceptions.PermissionDenied
        return user

    def check_digest_auth(self, request, password):
        """
        Check user authentication using HTTP Digest auth
        """
        response_hash = self.generate_response(request, password)
        return response_hash == self.auth_header['response']

    def generate_response(self, request, password):
        """
        Compile digest auth response

        If the qop directive's value is "auth" or "auth-int":
           RESPONSE = HASH(HA1:nonce:nc:cnonce:qop:HA2)
        If the "qop" directive is not present:
        (this construction is for compatibility with RFC 2069)
           RESPONSE = MD5(HA1:nonce:HA2)
        """
        HA1_value = self.create_HA1(password)
        HA2_value = self.create_HA2(request)

        if self.auth_header.get('qop') is None:
            response_data = ':'.join((
                HA1_value,
                self.auth_header['nonce'],
                HA2_value))
            response = self.hash_func(response_data)
        else:
            # qop is 'auth' or 'auth-int'
            response_data = ":".join((HA1_value,
                                      self.auth_header['nonce'],
                                      self.auth_header['nc'],
                                      self.auth_header['cnonce'],
                                      self.auth_header['qop'],
                                      HA2_value))
            response = self.hash_func(response_data)
        return response

    def create_HA1(self, password):
        """
        Create HA1 hash

        HA1 = HASH(A1) = HASH(username:realm:password)
        """
        if self.algorithm == 'MD5-sess':
            data = ':'.join((
                self.auth_header['username'],
                self.realm,
                password))
            data_hash = self.hash_func(data)
            A1 = ':'.join((
                data_hash,
                self.auth_header['nonce'],
                self.auth_header['cnonce']))
        else:
            A1 = ':'.join((
                self.auth_header['username'],
                self.realm,
                password))
        return self.hash_func(A1)

    def create_HA2(self, request):
        """
        Create HA2 hash

        If the "qop" directive's value is "auth" or is unspecified, then HA2 is:
            HA2 = HASH(A2) = HASH(request-method:digest-URI)
        If the qop directive's value is "auth-int", then HA2 is
            HA2 = HASH(A2) = HASH(request-method:digest-URI:MD5(entityBody))
        """

        if self.auth_header.get('qop') in ('auth', None):
            A2 = ':'.join((request.method, self.auth_header['uri']))
            return self.hash_func(A2)
        elif self.auth_header.get('qop') == 'auth-int':
            body_hash = self.hash_func(request.body)
            A2 = ':'.join((request.method,
                           self.auth_header['uri'],
                           body_hash))
            return self.hash_func(A2)

    def hash_func(self, data):
        alg_hash_func = self.hash_algorithms[self.algorithm]
        return alg_hash_func(data).hexdigest()


# TODO: OAuthAuthentication
