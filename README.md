# SAML2 Authenticator for JupyterHub

This repository provides a subclass of
[jupyterhub.auth.Authenticator](https://jupyterhub.readthedocs.io/en/stable/api/auth.html#jupyterhub.auth.Authenticator)
that acts as a SAML2 Service Provider.  Direct it to an appropriately configured SAML2 Identity Provider and it will
allow single sign-on for JupyterHub.

This package takes code and inspiration from JupyterHub's
[OAuthenticator](https://github.com/jupyterhub/oauthenticator) and
Fang Li's [django-saml2-auth](https://github.com/fangli/django-saml2-auth)
package.

## Installation
Install into the python environment your JupyterHub will be using. You may need
`xmlsec` and its development libraries.

```pip install git+git://github.com/ImperialCollegeLondon/jupyter_saml2authenticator```

## Setup
You will need:
* A JupyterHub installation, configured to use https (note that the certificate
only needs to be trusted by your users' browsers).
* The `xmlsec` executable, with OpenSSL support.
* Access to a SAML2 Identity Provider (IdP).
* The metadata or metadata URL of the IdP.

### Configure the IdP
This package has currently only been tested against Azure Active Directory,
although it should work with any SAML2 IdP  (do let me know if you try it).  If
you are configuring your IdP then set the Entity ID and Reply URL to match the
above otherise just note them down.  Get the metadata URL (App Federation
Metadata URL) or download the metadata XML.  Discover what attributes will be
in an authenticated response, and what key the username will have.

### Configure the authenticator
In the `jupyterhub_config.py` file remove any references to other
authenticators and add the following lines.  Only one of the `saml2_metadata_*`
options is required.  Some IdPs will require the Entity ID too.  Other options
are, er, optional.

```python
from jupyter_saml2authenticator import Saml2Authenticator
c.JupyterHub.authenticator_class = Saml2Authenticator

# Metadata URL or file is required.  Use one of saml2_metadata_url or saml2_metadata_filename
#c.Saml2Authenticator.saml2_metadata_url = 'https://login.microsoftonline.com/xxx-xxx-xxx-xxx-xxx/federationmetadata/2007-06/federationmetadata.xml?appid=xxx-xxx-xxx-xxx-xxx'
#c.Saml2Authenticator.saml2_metadata_filename = 'path_to_file'

# The Entity-ID or Identifier is a URI (not necessarily a URL) that is unique to your app.
# Some IdPs require this in the request (Azure Active Directory does)
c.Saml2Authenticator.saml2_entity_id = 'https://myjupyterhubsite/saml2_auth/ent'

# The mapping between the saml2response from the IdP and the username you want.
# Your IdP will return a dictionary of values; the saml2_attribute_username is the key for the desired username field.
# This one works for Azure Active Directory.
c.Saml2Authenticator.saml2_attribute_username = 'http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name'

# Er, I don't know what this is. From django-saml2-auth:
# FormatString. Sets the Format property of authn NameIDPolicy 
# c.Saml2Authenticator.saml2_name_id_format

# Whether to remove any @domain parts of the returned username.  You might want to
# leave it in and handle user mapping with a username_map.  Defaults to True.  Does
# nothing if @domain part isn't present.
# c.Saml2Authenticator.saml2_strip_username = True

# The URL Jupyterhub will use for logging in.
# Defaults to /saml2_auth/login (NB, relative to http[s]://myjupyterhubsite/hub)
# c.Saml2Authenticator.saml2_login_url = r'/saml2_auth/login'

# The URL Jupyterhub will expect the SAML2 response to be POSTed back to.
# This is the Reply-To / Assertion Consumer Service URL.
# It is strongly recommended that this be https, or the response token
# could be tampered with (some IdPs require https).
# Defaults to /saml2_auth/acs (NB, relative to http[s]://myjupyterhubsite/hub)
# c.Saml2Authenticator.saml2_acs_url = r'/saml2_auth/acs'
```
The `saml2_login_url` and `saml2_acs_url` URLs need not be accessible
externally.  SAML2 authentication is mediated by the user's browser; as long as
they can reach both the URLs and the IdP everything should work. This means you
have have ACS URLs like `https://localhost:8000/hub/saml2_auth/acs` if you want
to test things.

