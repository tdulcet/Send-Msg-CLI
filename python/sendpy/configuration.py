import concurrent.futures
import configparser
import getpass
import operator
import os
import re
import smtplib
import ssl
import sys
import time
import xml.etree.ElementTree as ET
from email.utils import parseaddr

import requests
from requests.exceptions import HTTPError, RequestException

try:
    import idna
except ImportError:

    def punycode(hostname):
        """Converts a given hostname to its Punycode representation."""
        return hostname.lower().encode("idna").decode("utf-8")

else:

    def punycode(hostname):
        """Converts a given hostname to its Punycode representation."""
        return idna.encode(hostname.lower(), uts46=True).decode("utf-8")


"""Copyright © Daniel Connelly and Teal Dulcet

   The purpose of this file is to save a configured person's settings
   for later use so they do not have to repeat cmdline arguments.
"""

parser = configparser.ConfigParser()
CONFIG_FILE = os.path.expanduser("~/.sendpy.ini")
parser.read([CONFIG_FILE])

context = ssl.create_default_context()

NONE = "plain"
STARTTLS = "STARTTLS"
SSL = "SSL"

# YES_REGEX = re.compile(locale.nl_langinfo(locale.YESEXPR))
YES_REGEX = re.compile(r"^[yY]")
# NO_REGEX = re.compile(locale.nl_langinfo(locale.NOEXPR))
NO_REGEX = re.compile(r"^[nN]")


def dns_lookup(domain, atype):
    """Perform a DNS lookup for the given domain and record type using Cloudflare's DNS over HTTPS (DoH) service."""
    try:
        r = requests.get(
            # "https://cloudflare-dns.com/dns-query", # Cloudflare
            # "https://dns.google/resolve", # Google Public DNS
            "https://mozilla.cloudflare-dns.com/dns-query",
            params={"name": domain, "type": atype},
            headers={"accept": "application/dns-json"},
            timeout=5,
        )
        result = r.json()
        r.raise_for_status()
    except HTTPError as e:
        print(f"{result.get('error', result)}: {e}")
        return None
    except RequestException as e:
        print(e)
        return None

    return result


def create_regex(trie):
    """Generates a regular expression pattern from a given trie structure."""
    alternatives = []
    character_class = []

    for char, subtree in trie.items():
        if char:
            if "" in subtree and len(subtree) == 1:
                character_class.append(char)
            else:
                recurse = create_regex(subtree)
                alternatives.append(recurse + char)
                # alternatives.append(char + recurse)

    if character_class:
        alternatives.append(character_class[0] if len(character_class) == 1 else f"[{''.join(character_class)}]")

    result = alternatives[0] if len(alternatives) == 1 else f"(?:{'|'.join(alternatives)})"

    if "" in trie:
        if character_class or len(alternatives) > 1:
            result += "?"
        else:
            result = f"(?:{result})?"

    return result


def create_tree(arr):
    """Creates a regex pattern from a list of domain names."""
    tree = {}

    arr.sort(key=len, reverse=True)

    for s in arr:
        node = tree

        for char in reversed(".".join(punycode(label) if label != "*" else label for label in s.split("."))):
            # for char in punycode(s):
            node = node.setdefault(char, {})

        # Mark leaf
        node[""] = True

    return create_regex(tree).replace(".", r"\.").replace("*", r"[^.]+")


def parse_psl(file):
    """Parses a Public Suffix List (PSL) file and returns compiled regex patterns for suffixes and exceptions."""
    starttime = time.perf_counter()
    suffixes = []
    exceptions = []

    with open(file, encoding="utf-8") as f:
        for line in (r.strip() for r in f):
            if line and not line.startswith("//"):
                if line.startswith("!"):
                    exceptions.append(line[1:])
                else:
                    suffixes.append(line)

    suffixes_re = create_tree(suffixes)
    exceptions_re = create_tree(exceptions)

    suffixes_pattern = re.compile(rf"(?:^|\.)({suffixes_re})$")
    exceptions_pattern = re.compile(rf"(?:^|\.)({exceptions_re})$")

    endtime = time.perf_counter()
    print(f"Parsed PSL in {1000 * (endtime - starttime):n} ms.")

    return suffixes_pattern, exceptions_pattern


def get_psl():
    """Downloads Mozilla's Public Suffix List (PSL) if not already present and parses it."""
    file = "public_suffix_list.dat"
    if not os.path.isfile(file):
        print(f"Downloading Mozilla's Public Suffix List (PSL) to {file!r}")
        starttime = time.perf_counter()
        try:
            r = requests.get("https://publicsuffix.org/list/public_suffix_list.dat", timeout=5, stream=True)
            r.raise_for_status()
            with open(file, "wb") as f:
                length = int(r.headers["Content-Length"])
                if hasattr(os, "posix_fallocate"):  # Linux
                    os.posix_fallocate(f.fileno(), 0, length)
                for chunk in r.iter_content(chunk_size=None):
                    if chunk:
                        f.write(chunk)
        except RequestException as e:
            print(e)
            return None
        endtime = time.perf_counter()
        print(f"Downloaded PSL in {1000 * (endtime - starttime):n} ms.")
    else:
        print("Mozilla's Public Suffix List (PSL) is already downloaded")

    return parse_psl(file)


def get_domain(suffixes_pattern, exceptions_pattern, hostname):
    """Extracts the domain from a given hostname based on suffix and exception patterns."""
    suffix_result = suffixes_pattern.search(hostname)
    exception_result = exceptions_pattern.search(hostname)

    labels = hostname.split(".")
    alabels = (
        exception_result.group(1).split(".")[1:]
        if exception_result
        else suffix_result.group(1).split(".")
        if suffix_result
        else labels[-1:]
    )

    if len(labels) > len(alabels):
        # subdomain = ".".join(labels[: -(len(alabels) + 1)])
        return ".".join(labels[-(len(alabels) + 1) :])

    print(f"Error: Hostname has invalid suffix: {hostname!r}")
    return None


PLACEHOLDER_RE = re.compile(r"%(\w+)%")


def parse_autoconfig(xml_data, email, local_part, email_domain):
    """Parses the autoconfig XML data to extract SMTP server details with placeholders replaced by provided email information."""
    try:
        root = ET.fromstring(xml_data)
    except ET.ParseError:
        # print(e)
        return None

    if root.tag != "clientConfig":
        print(f"Error: Unexpected config root element tag {root.tag!r}")
        return None

    replacements = {"EMAILADDRESS": email, "EMAILLOCALPART": local_part, "EMAILDOMAIN": email_domain}

    def replacer(match):
        return replacements.get(match.group(1), match.group())

    for provider in root.findall("./emailProvider"):
        display_name = provider.findtext("displayName")
        display_name = PLACEHOLDER_RE.sub(replacer, display_name) if display_name else provider.get("id")
        # domains = [domain.text for domain in provider.findall("domain")]

        for server in provider.findall("./outgoingServer[@type='smtp']"):
            hostname = server.findtext("hostname")
            port = server.findtext("port")
            socket_type = server.findtext("socketType")
            username = server.findtext("username")
            # password = server.findtext("password")

            if not hostname or not port:
                continue

            hostname = PLACEHOLDER_RE.sub(replacer, hostname)

            if username:
                username = PLACEHOLDER_RE.sub(replacer, username)

            return display_name, hostname, int(port), socket_type, username

    return None


def get_email_config(domain, email, local_part, email_domain, https_only=False, use_optional_url=True):
    """Retrieve email configuration settings from the specified domain or Mozilla ISP database."""
    adomain = punycode(domain)
    print(f"Looking up configuration at e-mail provider {domain!r}…")
    for scheme in ("https://",) + (() if https_only else ("http://",)):
        for url, args in ((f"autoconfig.{domain}/mail/config-v1.1.xml", {"emailaddress": email}),) + (
            ((f"{domain}/.well-known/autoconfig/mail/config-v1.1.xml", None),) if use_optional_url else ()
        ):
            try:
                r = requests.get(scheme + url, params=args, timeout=5)
                r.raise_for_status()
                result = r.content
            except RequestException:
                # print(e)
                pass
            else:
                smtp_config = parse_autoconfig(result, email, local_part, email_domain)
                if smtp_config is not None:
                    # print("Configuration found at e-mail provider")
                    _, hostname, _, _, _ = smtp_config
                    if scheme == "http://" and not punycode(hostname).endswith(adomain):
                        print("Warning: The connection used to lookup the configuration did not use HTTPS and thus was not secure.")
                    return smtp_config

    # https://github.com/thunderbird/autoconfig
    print(f"Looking up configuration for {domain!r} in the Mozilla ISP database…")
    try:
        r = requests.get(f"https://autoconfig.thunderbird.net/v1.1/{adomain}", timeout=5)
        r.raise_for_status()
        result = r.content
    except RequestException:
        # print(e)
        pass
    else:
        smtp_config = parse_autoconfig(result, email, local_part, email_domain)
        if smtp_config is not None:
            # print("Configuration found in Mozilla ISP database")
            return smtp_config
    return None


def get_dns_config(domain, aemail_domain):
    """Retrieve the hostname and port from DNS SRV records for a given domain."""
    result = dns_lookup(domain, "SRV")
    if result is not None and not result["Status"] and "Answer" in result:
        records = []
        (question,) = result["Question"]
        for answer in result["Answer"]:
            if question["type"] == answer["type"]:
                fields = answer["data"].split()
                if len(fields) == 4:
                    priority, weight, port, target = fields
                    records.append((int(priority), int(weight), int(port), target))
                else:
                    print(f"Error parsing DNS SRV Record for the {domain!r} domain: {answer['data']!r}")

        for _, _, port, target in sorted(records, key=lambda x: (x[0], -x[1])):
            if target != ".":
                # print("Configuration found from DNS SRV Records")
                hostname = target.rstrip(".")
                if not result["AD"] and not hostname.endswith(aemail_domain):
                    print(
                        "Warning: The DNS SRV record used to lookup the configuration was not signed with DNS Security Extensions (DNSSEC)."
                    )
                return hostname, port

    return None


def test_server(hostname, port, socket_type):
    """Tests the connectivity and handshake of an SMTP server with the specified configuration."""
    cmd = "we-guess.mozilla.org"

    try:
        if socket_type == SSL:
            with smtplib.SMTP_SSL(hostname, port, context=context, timeout=5) as server:
                if not 200 <= server.ehlo(cmd)[0] < 300:
                    return False
        elif socket_type in {STARTTLS, NONE}:
            with smtplib.SMTP(hostname, port, timeout=5) as server:
                if socket_type == STARTTLS:
                    server.ehlo(cmd)
                    server.starttls(context=context)
                if not 200 <= server.ehlo(cmd)[0] < 300:
                    return False
    except (OSError, ssl.CertificateError, smtplib.SMTPException):
        # print(e)
        return False

    return True


# RE = re.compile(r"^((.{1,64}@[\w.-]{4,254})|(.*) *<(.{1,64}@[\w.-]{4,254})>)$")
EMAILRE = re.compile(
    r'^(?=.{6,254}$)(?=.{1,64}@)((?:(?:[^@"(),:;<>\[\\\].\s]|\\[^():;<>.])+|"(?:[^"\\]|\\.)+")(?:\.(?:(?:[^@"(),:;<>\[\\\].\s]|\\[^():;<>.])+|"(?:[^"\\]|\\.)+"))*)@((?:(?:xn--)?[^\W_](?:[\w-]{0,61}[^\W_])?\.)+(?:xn--)?[^\W\d_]{2,63})$',
    re.U,
)


def email_autoconfig(email):
    """Automatically configures email settings based on the provided email address."""
    aemail = EMAILRE.match(email)
    if not aemail:
        print(f"Error: Could not parse e-mail address {email!r}")
        return None
    local_part, email_domain = aemail.groups()
    aemail_domain = punycode(email_domain)

    # https://datatracker.ietf.org/doc/draft-ietf-mailmaint-autoconfig/
    smtp_config = get_email_config(email_domain, email, local_part, email_domain)
    if smtp_config is not None:
        return smtp_config

    print("Looking up incoming mail domain (DNS MX Record)")
    result = dns_lookup(aemail_domain, "MX")
    if result is not None and not result["Status"] and "Answer" in result:
        records = []
        (question,) = result["Question"]
        for answer in result["Answer"]:
            if question["type"] == answer["type"]:
                fields = answer["data"].split()
                if len(fields) == 2:
                    priority, target = fields
                    records.append((int(priority), target))
                else:
                    print(f"Error parsing DNS MX Record for the {email_domain!r} domain: {answer['data']!r}")

        for _, target in sorted(records, key=operator.itemgetter(0)):
            mx_hostname = target.rstrip(".").lower()
            print(f"Found mail domain {mx_hostname!r}")
            suffixes_pattern, exceptions_pattern = get_psl()
            mx_base_domain = get_domain(suffixes_pattern, exceptions_pattern, mx_hostname)
            if mx_base_domain:
                print(f"Found base domain {mx_base_domain!r} for {mx_hostname!r}")
                mx_full_domain = ".".join(mx_hostname.split(".")[1:])
                for domain in (mx_base_domain,) + ((mx_full_domain,) if len(mx_full_domain) > len(mx_base_domain) else ()):
                    if domain != aemail_domain:
                        smtp_config = get_email_config(domain, email, local_part, email_domain, True, False)
                        if smtp_config is not None:
                            _, hostname, _, _, _ = smtp_config
                            if not result["AD"] and not punycode(hostname).endswith(aemail_domain):
                                print(
                                    "Warning: The DNS MX record used to lookup the mail domain was not signed with DNS Security Extensions (DNSSEC)."
                                )
                            return smtp_config
            break

    # https://datatracker.ietf.org/doc/html/rfc6186
    # https://datatracker.ietf.org/doc/html/rfc8314#section-5.1
    print("Looking up DNS SRV Records for configuration…")
    for label, security in (("_submissions._tcp.", SSL), ("_submission._tcp.", STARTTLS)):
        smtp_config = get_dns_config(label + aemail_domain, aemail_domain)
        if smtp_config is not None:
            hostname, port = smtp_config
            return hostname, hostname, port, security, None

    print("Trying common server names…")
    configs = []
    for hostname in ("smtp." + email_domain, "mail." + email_domain, email_domain):
        for socket_type, port in ((SSL, 465), (STARTTLS, 587), (STARTTLS, 25), (NONE, 587), (NONE, 25)):
            configs.append((hostname, port, socket_type))

    with concurrent.futures.ThreadPoolExecutor(len(configs)) as executor:
        futures = [executor.submit(test_server, *config) for config in configs]

    for future, (hostname, port, socket_type) in zip(futures, configs):
        if future.result():
            # print("Configuration found by trying common server names.")
            return email_domain, hostname, port, socket_type, None

    return None


def config_email(args):
    """Configures or reconfigures settings for send-msg-cli then writes the change to file."""
    section = "Email"
    if not parser.has_section(section):
        parser.add_section(section)

    fromemail = args.fromemail
    while not fromemail:
        fromemail = input("From e-mail address, e.g., 'User <user@example.com>': ")
    print("\nAttempting to lookup the configuration")
    tls = starttls = smtp_server = username = None
    _, fromaddress = parseaddr(fromemail)
    smtp_config = email_autoconfig(fromaddress or fromemail)
    if smtp_config is not None:
        display_name, hostname, port, socket_type, username = smtp_config
        smtp_server = f"{hostname}:{port}"
        security = None
        if socket_type:
            if socket_type == SSL:
                tls = True
                security = "SSL/TLS"
            elif socket_type == STARTTLS:
                starttls = True
                security = "StartTLS"
            elif socket_type == NONE:
                security = "No Encryption"
            else:
                security = f"Unknown ({socket_type!r})"
        print(
            f"""Outgoing (SMTP) server configuration found for {display_name!r}:
	Hostname: {hostname!r}
	Port: {port}
	Connection security: {security}
	Username: {repr(username) if username else "Unknown"}
"""
        )
    else:
        print("Unable to find the configuration\n")
    smtp_server = args.smtp
    while not smtp_server:
        smtp_server = input("SMTP server (hostname and optional port), e.g., 'mail.example.com:465': ")
    tls = args.tls
    starttls = args.starttls
    if not (tls or starttls):
        while True:
            accept = input("Use a secure connection with SSL/TLS? (y/n): ").strip()
            yes_res = YES_REGEX.match(accept)
            no_res = NO_REGEX.match(accept)
            if yes_res or no_res:
                break
        tls = bool(yes_res)
        if not tls:
            while True:
                accept = input("Upgrade to a secure connection with StartTLS? (y/n): ").strip()
                yes_res = YES_REGEX.match(accept)
                no_res = NO_REGEX.match(accept)
                if yes_res or no_res:
                    break
            starttls = bool(yes_res)
    username = args.username or input("Optional username for this account, e.g., 'user@example.com': ")
    password = args.password or getpass.getpass("Optional password for this account: ")

    parser.set(section, "smtp", smtp_server)
    if tls:
        parser.set(section, "tls", str(tls))
    if starttls:
        parser.set(section, "starttls", str(starttls))
    parser.set(section, "fromemail", fromemail)
    parser.set(section, "username", username)
    parser.set(section, "password", password)

    with open(CONFIG_FILE, "w", encoding="utf-8") as configfile:
        parser.write(configfile)


def config_pgp():
    """Set the pgp passphrase to avoid future typing of the passphrase on the commandline."""
    section = "PGP"
    if not parser.has_section(section):
        parser.add_section(section)

        passphrase = getpass.getpass("PGP secret key passphrase: ")

        parser.set(section, "passphrase", passphrase)

        with open(CONFIG_FILE, "w", encoding="utf-8") as configfile:
            parser.write(configfile)

        return passphrase

    return parser.get(section, "passphrase")


def return_config(args):
    """Pull (and check) variables in the .ini file."""
    section = "Email"
    if not parser.has_section(section):
        print(
            "The SMTP server and from e-mail address are not provided and not set in the config file. Please provide the --smtp and --from options or set the config file with the --config option.",
            file=sys.stderr,
        )
        sys.exit(1)

    smtp_server = args.smtp or parser.get(section, "smtp")
    tls = args.tls
    starttls = args.starttls
    if not (tls or starttls):
        if parser.has_option(section, "tls"):
            tls = parser.getboolean(section, "tls")
        if parser.has_option(section, "starttls"):
            starttls = parser.getboolean(section, "starttls")
    fromemail = args.fromemail or parser.get(section, "fromemail")
    username = args.username or parser.get(section, "username")
    password = args.password or parser.get(section, "password")

    return smtp_server, tls, starttls, fromemail, username, password
