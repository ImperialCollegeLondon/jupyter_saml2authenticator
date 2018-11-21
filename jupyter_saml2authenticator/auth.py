import base64

from tornado import gen, web
from tornado.log import app_log

from jupyterhub.handlers import BaseHandler
from jupyterhub.auth import Authenticator, LocalAuthenticator
from jupyterhub.utils import url_path_join
from traitlets import Unicode, Bool, List

from saml2 import (
    BINDING_HTTP_POST,
    BINDING_HTTP_REDIRECT,
    entity,
)
from saml2.client import Saml2Client
from saml2.config import Config as Saml2Config

class Saml2ACSHandler(BaseHandler):
    """ This is where the browser POSTs its SAML2 message (probably redirected
    from authenticating with our IdP). We will attempt to log in a user, which
    will call the authenticate() method of SAML2Authenticator.  """

    def get_next_url(self, user=None):
        """Get the redirect target from the state field"""
        # JupyterHub 0.8 adds default .get_next_url for a fallback
        if hasattr(BaseHandler, 'get_next_url'):
            return super().get_next_url(user)
        return url_path_join(self.hub.server.base_url, 'home')

    @gen.coroutine
    def _login_user_pre_08(self):
        """login_user simplifies the login+cookie+auth_state process in JupyterHub 0.8

        _login_user_pre_08 is for backward-compatibility with JupyterHub 0.7
        """
        user_info = yield self.authenticator.get_authenticated_user(self, None)
        if user_info is None:
            return
        if isinstance(user_info, dict):
            username = user_info['name']
        else:
            username = user_info
        user = self.user_from_username(username)
        self.set_login_cookie(user)
        return user

    if not hasattr(BaseHandler, 'login_user'):
        # JupyterHub 0.7 doesn't have .login_user
        login_user = _login_user_pre_08

    @gen.coroutine
    def post(self):
        user = yield self.login_user()
        if user is None:
            # todo: custom error page?
            raise web.HTTPError(403)
        self.redirect(self.get_next_url(user))

class Saml2AuthLoginHandler(BaseHandler):

    def get(self):
        saml_client = self.authenticator.get_saml_client(self)
        _, info = saml_client.prepare_for_authenticate()

        redirect_url = None

        for key, value in info['headers']:
            if key == 'Location':
                redirect_url = value
                break

        return self.redirect(redirect_url)

class Saml2Authenticator(Authenticator):
    """Saml2Authenticator
    """

    login_handler = Saml2AuthLoginHandler
    acs_handler = Saml2ACSHandler

    login_service = Unicode(
        'SAML2 Single Sign-on',
        config=True,
        help="""Name for login service.  Shown to user
        on login button."""
    )

    saml2_metadata_filename = Unicode(
        config=True,
        help="""SAML2 Metadata file to use.
        If this is set it overrides saml2_metadata_url"""
    )

    saml2_metadata_url = Unicode(
        config=True,
        help="""SAML2 Metadata URL to use.
        Should be https`.  Overridden by saml2_metadata_filename"""
    )

    saml2_entity_id = Unicode(
        config=True,
        help="""SAML2 Entity ID / Identifier.
        Some IdPs need this (AAD).  Must be unique to your org."""
    )

    saml2_name_id_format = Unicode(
        config=True,
        # From django-saml2-auth
        help="""FormatString. Sets the Format property of authn NameIDPolicy
        """
    )

    saml2_strip_username = Bool(
        default_value=True,
        config=True,
        help="""Whether to strip @domain suffix from usernames.
        """
    )

    saml2_login_url = Unicode(
        default_value=r'/saml2_auth/login',
        config=True,
        help="""Whether to strip @domain suffix from usernames.
        """
    )

    saml2_acs_url = Unicode(
        default_value=r'/saml2_auth/acs',
        config=True,
        help="""The URL that starts the SAML2 auth
        """
    )

    saml2_attribute_username = Unicode(
        config=True,
        help="""The URL where the SAML2 response is POSTed.
        """
    )

    username_map = { 'scliffor': 'simon' }
    def get_current_domain(self, handler):
        return '{scheme}://{host}'.format(
            scheme=handler.request.protocol,
            host=handler.request.host,
        )

    def get_saml_client(self, handler):
        acs_url = self.get_current_domain(handler) + handler.reverse_url('saml2_acs_handler')
        if self.saml2_metadata_filename:
            metadata = {
                'local': [ self.saml2_metadata_filename ]
            }
        elif self.saml2_metadata_url:
            metadata = {
                'remote': [
                    {
                        "url": self.saml2_metadata_url,
                    },
                ]
            }
        else:
            raise web.HTTPError(500, 'No metadata provided')

        saml_settings = {
            'metadata': metadata,
            'service': {
                'sp': {
                    'endpoints': {
                        'assertion_consumer_service': [
                            (acs_url, BINDING_HTTP_REDIRECT),
                            (acs_url, BINDING_HTTP_POST)
                        ],
                    },
                    'allow_unsolicited': True,
                    'authn_requests_signed': False,
                    'logout_requests_signed': True,
                    'want_assertions_signed': True,
                    'want_response_signed': False,
                },
            },
        }

        if self.saml2_entity_id:
            saml_settings['entityid'] = self.saml2_entity_id

        if self.saml2_name_id_format:
            saml_settings['service']['sp']['name_id_format'] = self.saml2_name_id_format

        spConfig = Saml2Config()
        spConfig.load(saml_settings)
        spConfig.allow_unknown_attributes = True
        saml_client = Saml2Client(config=spConfig)
        return saml_client

    def login_url(self, base_url):
        return url_path_join(base_url, self.saml2_login_url)

    def get_handlers(self, app):
        return [
            (self.saml2_login_url, self.login_handler, None,
                'saml2_login_handler'),
            (self.saml2_acs_url, self.acs_handler, None,
                'saml2_acs_handler'),
        ]

    def normalize_username(self, username):
        '''username may be in form of user@domain.  Optionally
        strip the @domain part.  Then apply default normalization.
        '''
        if self.saml2_strip_username:
            ind = username.find('@')
            if ind != -1:
                return super().normalize_username(username[0:ind])
        return super().normalize_username(username)

    @gen.coroutine
    def authenticate(self, handler, data=None):
        saml_client = self.get_saml_client(handler)
        resp = handler.get_body_argument('SAMLResponse', None)
        next_url = '/'

        if not resp:
            raise web.HTTPError(400, "No SAML2 response found")

        try:
            authn_response = saml_client.parse_authn_request_response(
                resp, entity.BINDING_HTTP_POST)
        except:
            app_log.error('parse_..._response failed: %r',
                base64.b64decode(resp))
            raise
        if authn_response is None:
            raise web.HTTPError(400, "SAML2 response failed")

        user_identity = authn_response.get_identity()
        if user_identity is None:
            raise web.HTTPError(400, "no SAML2 user")

#        user_email = user_identity[settings.SAML2_AUTH.get('ATTRIBUTES_MAP', {}).get('email', 'Email')][0]
#        user_name = user_identity[settings.SAML2_AUTH.get('ATTRIBUTES_MAP', {}).get('username', 'UserName')][0]
#        user_first_name = user_identity[settings.SAML2_AUTH.get('ATTRIBUTES_MAP', {}).get('first_name', 'FirstName')][0]
#        user_last_name = user_identity[settings.SAML2_AUTH.get('ATTRIBUTES_MAP', {}).get('last_name', 'LastName')][0]

        app_log.info('user_identity: %r', user_identity)
        if not self.saml2_attribute_username:
            app_log.error('No saml2_attribute_username configured!')
            raise web.HTTPError(500)
        username = user_identity[self.saml2_attribute_username][0]
        return username

class LocalSaml2Authenticator(LocalAuthenticator, Saml2Authenticator):
    """A version that mixes in local system user creation"""
    pass
