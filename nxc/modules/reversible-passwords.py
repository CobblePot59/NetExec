from nxc.helpers.misc import CATEGORY
from nxc.parsers.ldap_results import parse_result_attributes


class NXCModule:
    name = "reversible-passwords"
    description = "List accounts whose password is stored with reversible encryption (userAccountControl ENCRYPTED_TEXT_PWD_ALLOWED)"
    supported_protocols = ["ldap"]
    category = CATEGORY.ENUMERATION

    UF_ENCRYPTED_TEXT_PWD_ALLOWED = 0x0080

    def options(self, context, module_options):
        """No options."""

    def on_login(self, context, connection):
        search_filter = f"(&(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:={self.UF_ENCRYPTED_TEXT_PWD_ALLOWED}))"
        resp = connection.search(searchFilter=search_filter, attributes=["sAMAccountName"])
        accounts = [entry["sAMAccountName"] for entry in parse_result_attributes(resp) if entry.get("sAMAccountName")]

        if not accounts:
            context.log.display("No account stores its password with reversible encryption")
            return

        context.log.success(f"Found {len(accounts)} account(s) storing their password with reversible encryption:")
        for account in accounts:
            context.log.highlight(account)
