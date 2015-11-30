#!/usr/bin/python3
# -*- coding: utf-8 -*-

import os
import re
import argparse
import getpass


def prepare_config(dns_names=[]):
    with open("/etc/ssl/openssl.cnf", 'r') as openssl_config:
        config = openssl_config.read()
    lines = config.splitlines()
    req_regex = re.compile('\s*\[\s*req\s*\]\s*')
    for number, line in enumerate(lines):
        if re.search(req_regex, line):
            lines.insert(number + 1, "req_extensions = v3_req")
            break
    v3req_regex = re.compile('\s*\[\s*v3_req\s*\]\s*')
    next_block_regex = re.compile('\s*\[\s*\w+\s*\]\s*')
    v3req_found = False
    for number, line in enumerate(lines):
        if v3req_found and re.search(next_block_regex, line) and len(dns_names) > 0:
            lines.insert(number, "subjectAltName = @alt_names")
            lines.insert(number + 1, "")
            lines.insert(number + 2, "[alt_names]")
            for name_no, name in enumerate(dns_names):
                lines.insert(number + 3 + name_no, "DNS." + str(name_no + 1) + " = " + name)
            lines.insert(number + 3 + len(dns_names), "")
            break
        if re.search(v3req_regex, line):
            v3req_found = True
    v3_ca_regex = re.compile('\s*\[\s*v3_ca\s*\]\s*')
    v3_ca_found = False
    for number, line in enumerate(lines):
        if v3_ca_found and re.search(next_block_regex, line) and len(dns_names) > 0:
            lines.insert(number, "subjectAltName = @alt_names")
            lines.insert(number + 1, "")
            lines.insert(number + 2, "[ v3_ca_has_san ]")
            lines.insert(number + 3, "subjectKeyIdentifier = hash")
            lines.insert(number + 4, "authorityKeyIdentifier = keyid:always,issuer:always")
            lines.insert(number + 5, "basicConstraints = CA:true")
            lines.insert(number + 6, "")
            break
        if re.search(v3_ca_regex, line):
            v3_ca_found = True
    with open("demoCA/openssl.cnf", 'w') as local_file:
        local_file.write("\n".join(lines) + "\n")


def create_certificate_chain():
    os.system("mkdir demoCA/newcerts")
    os.system("touch demoCA/index.txt")
    os.system("echo 1000 > demoCA/serial")
    os.system("openssl genrsa -aes256 -out CA.key -passout pass:" + ca_password + " " + str(key_size) + "")
    locality_option = ""
    if args.locality and len(args.locality) > 0:
        locality_option = "/L=" + args.locality
    organizational_unit_option = ""
    if args.organizational_unit and len(args.organizational_unit) > 0:
        organizational_unit_option = "/OU=" + args.organizational_unit
    email_option = ""
    if args.email and len(args.email) > 0:
        email_option = "/emailAddress=" + args.email
    os.system("openssl req -config " + os.path.abspath("demoCA/openssl.cnf") + " -x509 -new -nodes " +
              "-extensions v3_ca_has_san -utf8 " +
              "-key CA.key -passin pass:" + ca_password + " " +
              "-subj \"/C=" + country + "/ST=" + state + locality_option +
              "/O=" + company_name + organizational_unit_option + "/CN=" + args.domain + "-CA-root" +
              email_option + "\" " +
              "-days " + str(days) + " " +
              "-out CA.pem -sha512")
    os.system("openssl genrsa -aes256 -out intermediate.key -passout pass:" + intermediate_password + " " +
              str(key_size))
    os.system("openssl req -config " + os.path.abspath("demoCA/openssl.cnf") + " " +
              "-sha256 -new -utf8 -key intermediate.key " +
              "-passin pass:" + intermediate_password + " " +
              "-subj \"/C=" + country + "/ST=" + state + locality_option +
              "/O=" + company_name + organizational_unit_option + "/CN=" + args.domain + "-CA-intermediate" +
              email_option + "\" " +
              "-out intermediate.csr")
    os.system("openssl ca -config " + os.path.abspath("demoCA/openssl.cnf") + " " +
              "-keyfile CA.key -cert CA.pem -extensions v3_ca -notext -md sha256 -batch " +
              "-passin pass:" + ca_password + " -in intermediate.csr -out intermediate.pem")
    os.system("openssl verify -CAfile CA.pem intermediate.pem")
    os.system("openssl genrsa -aes256 -out server.key -passout pass:1234 " + str(key_size))
    os.system("openssl req -config " + os.path.abspath("demoCA/openssl.cnf") + " -sha256 -new -utf8 " +
              "-key server.key -passin pass:1234 -subj \"/C=" + country + "/ST=" + state + locality_option +
              "/O=" + company_name + organizational_unit_option + "/CN=" + args.domain + email_option + "\" " +
              "-out server.csr")
    os.system("mv server.key server.key.orig")
    os.system("openssl rsa -in server.key.orig -out server.key -passin pass:1234")
    os.system("rm server.key.orig")
    os.system("openssl ca -config " + os.path.abspath("demoCA/openssl.cnf") + " " +
              "-keyfile intermediate.key -passin pass:" + intermediate_password + " " +
              "-cert intermediate.pem -notext -md sha256 -batch " +
              "-days " + str(days) + " -in server.csr -out server.pem")
    os.system("cat server.pem intermediate.pem CA.pem > chain.pem")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate a certificate chain.")
    parser.add_argument('domain', help="Domain name without www.")
    parser.add_argument('-s', '--key-size',
                        type=int,
                        help="Size of the key in bits. 2048 bit is quite common. " +
                             "4096 bit is more secure and the default.")
    parser.add_argument('-d', '--days',
                        type=int,
                        help="Validity time in days. Default is 2492 (7 years).")
    parser.add_argument('--country',
                        type=str,
                        help="Country code with two letters. Default is DE.")
    parser.add_argument('--state',
                        type=str,
                        help="State or region. Default is \"Some-State\".")
    parser.add_argument('--locality',
                        type=str,
                        help="City or place.")
    parser.add_argument('--company-name',
                        type=str,
                        help="Company name. Default is the domain.")
    parser.add_argument('--organizational-unit',
                        type=str,
                        help="Name of your unit or team.")
    parser.add_argument('--email',
                        type=str,
                        help="Email.")
    parser.add_argument('--ca-password',
                        type=str,
                        help="CA key password. If omitted it will be prompted.")
    parser.add_argument('--intermediate-password',
                        type=str,
                        help="intermediate key password. If omitted it will be prompted.")
    args = parser.parse_args()
    if args.key_size:
        key_size = args.key_size
    else:
        key_size = 4096
    if args.days:
        days = args.days
    else:
        days = 2492
    if args.country:
        country = str.capitalize(args.country[:2])
    else:
        country = "DE"
    if args.state:
        state = args.state
    else:
        state = "Some-State"
    if args.company_name:
        company_name = args.company_name
    else:
        company_name = args.domain
    os.system("mkdir demoCA")
    prepare_config([args.domain, "www." + args.domain])
    if args.ca_password:
        ca_password = args.ca_password
    else:
        ca_password = getpass.getpass("Enter pass phrase for CA.key: ")
    if args.intermediate_password:
        intermediate_password = args.intermediate_password
    else:
        intermediate_password = getpass.getpass("Enter pass phrase for intermediate.key: ")
    create_certificate_chain()
    #os.system("rm demoCA/openssl.cnf")
