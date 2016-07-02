#!/usr/bin/env python3

# env vars : CATTLE_URL, CATTLE_ACCESS_KEY, CATTLE_SECRET_KEY

import datetime
import os
import subprocess
import uuid
import json

import requests
import yaml

import libs.acme_tiny as acme_tiny


def get_chain(config):
    if "chain" not in config:
        return None
    r = requests.get(config["chain"])
    if r.status_code != 200:
        raise Exception('Unable to get chain cert: ' + str(r.status_code) + ' - ' + r.text)
    return r.text


def rancher_get_certs():
    r = requests.get(os.environ['CATTLE_URL'] + "/certificates",
                     auth=(os.environ['CATTLE_ACCESS_KEY'], os.environ['CATTLE_SECRET_KEY']))
    if r.status_code != 200:
        raise Exception('Rancher returned non-200 code: ' + str(r.status_code) + ' - ' + r.text)
    return r.json()["data"]


def rancher_save_cert(name, private_key, cert, chain, link=None):

    payload = {'key': private_key, 'cert': cert, 'certChain': chain}

    if link is None:  # New certificate
        payload["name"] = name
        r = requests.post(os.environ['CATTLE_URL'] + "/certificates", data=json.dumps(payload),
                          headers={'Content-Type': 'application/json'},
                          auth=(os.environ['CATTLE_ACCESS_KEY'], os.environ['CATTLE_SECRET_KEY']))

    else:  # Update existing certificate
        r = requests.put(link, data=json.dumps(payload),
                         headers={'Content-Type': 'application/json'},
                         auth=(os.environ['CATTLE_ACCESS_KEY'], os.environ['CATTLE_SECRET_KEY']))

    if r.status_code not in [200, 201]:
        raise Exception('Rancher returned non-200 code: ' + str(r.status_code) + ' - ' + r.text)


def openssl(args, input=None):
    proc = subprocess.Popen(["openssl"] + args, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if input is not None:
        out, err = proc.communicate(input)
    else:
        out, err = proc.communicate()
    if proc.returncode != 0:
        raise IOError("OpenSSL Error: {0}".format(err.decode("utf-8")))
    return out



def do_cert(config, name, domains, link=None):
    print("Creating certificate", name, "for domains:", ', '.join(domains))

    if len(domains) < 1:
        raise Exception("No domains for certificate")

    private_key_file = "/tmp/" + uuid.uuid4().hex
    csr_file = "/tmp/" + uuid.uuid4().hex

    print("Generating private key to " + private_key_file + "...")
    openssl(["genrsa", "-out", private_key_file, str(config["key_length"])])

    with open(private_key_file, 'r') as f:
        private_key = f.read()

    print("Generating CSR to " + csr_file + "...")
    if len(domains) == 1:
        openssl(["req", "-new", "-sha256", "-key", private_key_file, "-out", csr_file, "-subj", "/CN=" + domains[0]])
    else:
        csr_config_file = "/tmp/" + uuid.uuid4().hex
        print("Generating CSR config to " + csr_config_file + "...")
        with open("/etc/ssl/openssl.cnf", "r") as f:
            openssl_config = f.read()
        openssl_config += "\n[SAN]\nsubjectAltName=DNS:" + ',DNS:'.join(domains) + "\n"
        with open(csr_config_file, "w") as f:
            f.write(openssl_config)
        openssl(["req", "-new", "-sha256", "-key", private_key_file, "-out", csr_file, "-subj", "/", "-reqexts", "SAN", "-config", csr_config_file])
        print("Deleting CSR config file...")
        os.remove(csr_config_file)

    print("Deleting private key file...")
    os.remove(private_key_file)

    print("Signing CSR using acme_tiny...")
    cert = acme_tiny.get_crt(config["account_key"], csr_file, config["acme_dir"], CA=config["ca"])

    print("Deleting CSR file...")
    os.remove(csr_file)

    print("Getting chain...")
    chain = get_chain(config)

    # TODO: Backup certificate & key ?

    print("Saving cert in Rancher...")
    rancher_save_cert(name, private_key, cert, chain, link)


def load_config():

    with open("config/config.yml", "r") as f:
        config = yaml.load(f)

    # Strip cert names and domains
    for cert in config["certs"]:
        cert["name"] = cert["name"].strip()
        for i in range(len(cert["domains"])):
            cert["domains"][i] = cert["domains"][i].strip()

    return config


def contains_sublist(lst, sublst):
    for e in sublst:
        if e not in lst:
            return False
    return True


def main():
    now = datetime.datetime.now()
    print("*** Rancher Auto Certs started", now.strftime("%Y-%m-%d %H:%M"), "***")

    config = load_config()

    print("Using CA: " + config["ca"])
    print("Using account key: " + config["account_key"])

    print("Getting certificates from Rancher...")
    rancher_certs = rancher_get_certs()

    rancher_certs_by_name = {}
    for cert in rancher_certs:
        rancher_certs_by_name[cert["name"].strip()] = cert

    print("Found certs from Rancher:")
    for cert in rancher_certs:
        print("- " + cert["name"] + ": " + ', '.join(cert["subjectAlternativeNames"]))
    print("Found certs from config:")
    for cert in config["certs"]:
        print("- " + cert["name"] + ": " + ', '.join(cert["domains"]))

    to_do = []  # List of (remaining_days, name, domains, link) for certs to make

    print("Checking certs from Rancher:")
    for cert_config in config["certs"]:
        name = cert_config["name"]
        domains = cert_config["domains"]
        if name not in rancher_certs_by_name:
            print("- Cert " + name + " does not exists")
            to_do.append((0, name, domains, None))
        else:
            rancher_cert = rancher_certs_by_name[name]
            link = rancher_cert["links"]["self"]
            if contains_sublist(rancher_cert["subjectAlternativeNames"], domains):
                cert_exp = datetime.datetime.strptime(rancher_cert["expiresAt"], "%a %b %d %H:%M:%S %Z %Y")
                remaining_days = (cert_exp - now).days
                print("- Cert " + name + " expires in", remaining_days, "days")
                if remaining_days < 30:
                    to_do.append((remaining_days, name, domains, link))
            else:
                print("- Cert " + name + " is missing domains")
                to_do.append((0, name, domains, link))

    # Renew certs in the order they expire
    to_do.sort()
    for (_, name, domains, link) in to_do:
        do_cert(config, name, domains, link)

    # TODO: Update load balancers ?

    print("*** Rancher Auto Certs done", now.strftime("%Y-%m-%d %H:%M"), "***")


if __name__ == '__main__':
    main()  # TODO: Send a mail if sth goes wrong ?
