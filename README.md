# sso2linuxuser
Simple webserver that grants creation of a linux user after succesfull SSO authentication / authorization. Right know only implements  SAML.

## Usage

### Installation
Use pip:

    pip install git+https://github.com/gatoniel/sso2linuxuser
    
### Configuration as systemd service

Add a separate non-root user

    sudo useradd -s /sbin/nologin sso2linuxuser
    sudo groupadd certs-read
    sudo usermod -a -G certs-read sso2linuxuser

    cd /etc/pki/
    sudo chgrp certs-read key-nopass.pem
    sudo chmod g+r key-nopass.pem

    sudo chown sso2linuxuser:sso2linuxuser -R /path/to/config/files
    
This is an example service file:

    [Unit]
    Description=sso2linuxuser
    After=network-online.target

    [Service]
    User=sso2linuxuser
    AmbientCapabilities=CAP_SETUID CAP_SETGID
    Restart=on-failure
    ExecStart=/opt/jupyterhub/bin/sso2linuxuser --lowercase_uname --https_reverse_proxy --saml_path /path/to/config/files

    [Install]
    WantedBy=multi-user.target

Capabilities CAP_SETUID CAP_SETGID are a must have in order to switch to root in subprocesses to create users and make PAM calls to set the password.

Now you have to add settings.json and certificate files as described for [python3-saml](https://github.com/onelogin/python3-saml/) to /path/to/config/files.

## Idea
For some web-services, e.g. JupyterHub, you need an actual linux user on the machine, to manage access rights for data persistence. Not to mention security issues: With JupyterHub users are granted full access to computational ressources, there are nearly no limits to the user, hence we want to log user activities with audit (loginuid). Then it is neccessary that each user has a unique ID - no guest logins... With this webservice users can create a linux user on the machine after they authenticated themselves via SAML. That way we do not need to use JupyterHubs SAMLAuthenticator and can rely on the working PAMAuthenticator. On top, we can create separate linux users ourselves for people that cannot use the SAML authentication, since they have no valid account (e.g. students vs staff).

### implementation
I want to use the python framework [tornado](https://www.tornadoweb.org/en/stable/) together with [python3-saml](https://github.com/onelogin/python3-saml/). I want to run the webservice as a non-root user that can transition to root to create users. It might also be possible, to add the non-root user to the sudoers file or to grant access to shadow group.

We will use `subprocess.Popen(["adduser", USERNAME])` for creating a user and [pamelas](https://github.com/minrk/pamela) change_password function to create a new password.

### future ideas...
When password authentification is forbidden via ssh, one could upload the public key via this interface. Add OAuth and other SSO authentication methods.

## security issues
I am aware, that this service poses security threats to the server. Thus I will at the moment not allow password changes. Every authenticated user can only create one linux account, since the username is copied from the SAML id.

## known issues
- The logging with debug does not work correctly.
- SingleLogoutService is not implemented, but is not really needed...
