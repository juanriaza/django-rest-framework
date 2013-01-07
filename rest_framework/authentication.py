"""
Provides a set of pluggable authentication policies.
"""

import os
import base64
import urllib2
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

    You can use another model different than User:
        - Change: model, username_field, secret_field

    Based on
    # http://flask.pocoo.org/snippets/31/
    # https://github.com/shanewholloway/werkzeug/blob/master/werkzeug/contrib/authdigest.py
    # https://github.com/Almad/django-http-digest
    """
    realm = 'django-rest-framework'
    model = User
    username_field = 'username'
    secret_field= 'password'
    hash_algorithms = {
        'md5': hashlib.md5,
        'sha1': hashlib.sha1
    }
    algorithm = 'md5'

    def authenticate(self, request):
        """
        Returns a `User` if a correct username and password have been supplied
        using HTTP Digest authentication.  Otherwise returns `None`.
        """
        if 'HTTP_AUTHORIZATION' in request.META:
            headers = self.parse_authorization_header(request.META['HTTP_AUTHORIZATION'])

            if headers['realm'] == self.realm\
            and self.verify(headers, request.method, request.get_full_path()):
                return 'YAY'
        print 'NOT AUTH'

    def authenticate_header(self, request):
        nonce = self.digest_hash_alg(self.realm, os.urandom(8))
        header_format = 'Digest realm="%(realm)s", qop="%(qop)s", nonce="%(nonce)s", opaque="%(opaque)s"'
        header = header_format % {
            'realm' : self.realm,
            'qop' : 'auth',
            'nonce' : nonce,
            'opaque' : 'CHECK_THIS'}
        return header

    def verify(self, headers, req_method, req_path):
        """
        Compare computed secret to secret from authentication backend.
        """
        client_secret = headers['response']
        server_secret = self.get_server_secret(headers, req_method, req_path)
        return client_secret == server_secret

    def get_a1(self, headers):
        username = headers['username']
        params = {self.username_field: username}
        inst = self.model.objects.get(**params)
        a1 = getattr(inst, self.secret_field)
        return a1

    def get_server_secret(self, headers, req_method, req_path):
        """
        Compute server secret from provided, partially computed values.
        """
        assert 'auth' == headers['qop']

        # A2, according to section 3.2.2.3
        a2 =  self.digest_hash_alg(req_method, req_path)

        request_digest = (
            self.get_a1(headers),
            headers['nonce'],
            headers['nc'],
            headers['cnonce'],
            headers['qop'],
            a2)
        server_secret = self.digest_hash_alg(request_digest)
        return server_secret

    def parse_authorization_header(self, header):
        # TODO: check https://github.com/kennethreitz/requests/blob/master/requests/utils.py#L167
        if not header.startswith('Digest '):
            raise exceptions.ParseError('Header do not start with Digest')
        header = header[len('Digest '):]

        # Convert the auth params to a dict
        items = urllib2.parse_http_list(header)
        params = urllib2.parse_keqv_list(items)

        required = ('username', 'realm', 'nonce', 'uri', 'response')

        for field in required:
            if field not in params:
                raise exceptions.ParseError('Required field %s not found' % field)

        # check for qop companions (sect. 3.2.2)
        if 'qop' in params and 'cnonce' not in params and 'cn' in params:
            raise exceptions.ParseError('qop sent without cnonce and cn')

        return params

    def digest_hash_alg(self, *args):
        data = ':'.join(map(str, args))
        hash_func = self.hash_algorithms[self.algorithm]
        return hash_func(data).hexdigest()


# TODO: OAuthAuthentication
