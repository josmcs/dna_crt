from ldap3 import Server, Connection, ALL, NTLM, SUBTREE

LDAP_URI = "ldap://hca.corpad.net"
LDAP_BASE_DN = "DC=hca,DC=corpad,DC=net"
LDAP_BIND_DN = "SADVSVCNETWLDAP01@hca.corpad.net"
LDAP_BIND_PASS = "0QF}XQ!f4N|{=s8]b5gw+UumQPwpwAP("
LDAP_ALLOWED_GROUP = "CN=SADV-DNAC-SCRT,OU=G25388,OU=25388,DC=hca,DC=corpad,DC=net"
LDAP_UPN_SUFFIX = "@hca.corpad.net"

def authenticate(username, password):
    # User must log in with UPN
    user_upn = username + LDAP_UPN_SUFFIX

    # 1. Bind with service account
    server = Server(LDAP_URI, get_info=ALL)
    try:
        conn = Connection(server, LDAP_BIND_DN, LDAP_BIND_PASS, auto_bind=True)
    except Exception as e:
        print("Service bind failed:", e)
        return None

    # 2. Search for the user DN
    search_filter = f"(userPrincipalName={user_upn})"
    conn.search(
        search_base=LDAP_BASE_DN,
        search_filter=search_filter,
        search_scope=SUBTREE,
        attributes=["distinguishedName", "mail", "displayName", "memberOf"]
    )

    if not conn.entries:
        return None

    entry = conn.entries[0]
    user_dn = entry.distinguishedName.value

    # 3. Check group membership
    groups = entry.memberOf.values if "memberOf" in entry else []
    if LDAP_ALLOWED_GROUP not in groups:
        return None

    # 4. Validate user password by binding as the user
    try:
        user_conn = Connection(server, user_dn, password, auto_bind=True)
    except Exception:
        return None

    # 5. Return user info for session
    return {
        "username": username,
        "email": entry.mail.value,
        "name": entry.displayName.value,
        "role": "authorized"
    }
