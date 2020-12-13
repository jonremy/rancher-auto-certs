Rancher Auto Certs
==================

This is a Docker image made for [Rancher 1](https://rancher.com/docs/rancher/v1.6/en/) users.

It generates certificates with [Let's Encrypt](https://letsencrypt.org/) ACME v2 to match what's in its configuration
file, and imports them to Rancher using the API.

This is mainly a Python 3 script that uses [ACME Tiny](https://github.com/diafygi/acme-tiny).


Installation
------------

### Get your Let's Encrypt Account Key

If you already used Let's Encrypt with the `certbot` client, you can copy your account key `.json` file
(found in `/etc/letsencrypt`) and convert it to the format used by this script using the `conv.py` script.

Otherwise, you can generate a new key with : `openssl genrsa 4096 > account.key`

### Create the Rancher service

This image declares two volumes:
* `/usr/src/app/config` for the configuration file `config.yml` and can be used to store the Let's Encrypt account keys.
* `/media/acme-challenge` is where the challenge files will be put.

This image doesn't take care of making the ACME Challenge files available from the web. If you don't already have a web
server to do that, you can create a `nginx` service and mount the volume with the challenge files to be available at the
`/.well-known/acme-challenge` path. You need to configure your frontend or loadbalancher to make all requests to the
path `/.well-known/acme-challenge` - on all the domains you want certificates for - go to the right service.

The script needs tokens to access the Rancher API. You just need to add the following labels to the service and Rancher
will automatically create environment vars for the API access :
* `io.rancher.container.create_agent=true`
* `io.rancher.container.agent.role=environment`

Here is an example Rancher config:
```
auto-certs:
  labels:
    io.rancher.container.create_agent: 'true'
    io.rancher.container.agent.role: environment
  image: jremy/rancher-auto-certs:X.Y.Z
  volumes:
    - auto-certs-config:/usr/src/app/config
    - auto-certs-acme-challenge:/media/acme-challenge
httpd-acme-challenge:
  image: nginx:1.10
  volumes:
    - auto-certs-acme-challenge:/usr/share/nginx/html/.well-known/acme-challenge:ro
```

### Pimp the config

The script config file is a [YAML](https://en.wikipedia.org/wiki/YAML) file.

Each certificate is defined with a `name` and a list of `domains`. The name is only used for Rancher.
Usually the name is one of the certificate domains, but this is not a restriction.

By default the config points to the Let's Encrypt staging environment, which generates invalid certificates.
To use the production environment, change the `ca_directory` value to `https://acme-v02.api.letsencrypt.org/directory`.


Usage
-----

The script will run once a day, and renew certificates if needed.

When you update the config, just restart the container in Rancher for the script to re-run.

