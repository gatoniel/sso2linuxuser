# sso2linuxuser
Simple webserver that grants creation of a linux user after succesfull SSO authentication / authorization

## Idea:
For some web-services, e.g. JupyterHub, you need an actual linux user on the machine, to manage access rights for data persistence. Not to mention security issues: With JupyterHub users are granted full access to computational ressources, there are nearly no limits to the user, hence we want to log user activities with audit (loginuid). Then it is neccessary that each user has a unique ID - no guest logins... With this webservice users can create a linux user on the machine after they authenticated themselves via SAML. That way we do not need to use JupyterHubs SAMLAuthenticator and can rely on the working PAMAuthenticator. On top, we can create separate linux users ourselves for people that cannot use the SAML authentication, since they have no valid account (e.g. students vs staff).

### implementation
I want to use the python framework [tornado](https://www.tornadoweb.org/en/stable/) together with [python3-saml](https://github.com/onelogin/python3-saml/). I want to run the webservice as a non-root user that can transition to root to create users. It might also be possible, to add the non-root user to the sudoers file or to grant access to shadow group.

We will use `subprocess.Popen(["adduser", USERNAME])` for creating a user and [pamelas](https://github.com/minrk/pamela) change_password function to create a new password.

## future ideas...
When password authentification is forbidden via ssh, one could upload the public key via this interface.

## security issues
I am aware, that this service poses security threats to the server. Thus I will at the moment not allow password changes. Every authenticated user can only create one linux account, since the username is copied from the SAML id.
