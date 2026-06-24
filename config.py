import os
from dotenv import load_dotenv

# Load .env file
load_dotenv()

# LDAP Configuration
LDAP_SERVER = "ldap://hca.corpad.net"
LDAP_DOMAIN = "hca.corpad.net"
LDAP_SEARCH_BASE = "DC=hca,DC=corpad,DC=net"

LDAP_BIND_DN = "SADVSVCNETWLDAP01@hca.corpad.net"
LDAP_BIND_PASS = os.getenv("LDAP_BIND_PASS")

LDAP_ALLOWED_GROUP = "CN=SADV-DNAC-SCRT,OU=G25388,OU=25388,DC=hca,DC=corpad,DC=net"
