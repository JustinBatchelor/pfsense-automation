#!/usr/bin/python
"""Verify live DNS over both transports, independently of pfrest."""

from ansible.module_utils.basic import AnsibleModule
import ipaddress
import dns.message
import dns.query
import dns.rcode
import dns.rdatatype


def main():
    module = AnsibleModule(
        argument_spec={
            "records": {"type": "list", "elements": "dict", "required": True},
            "server": {"type": "str", "required": True},
            "timeout": {"type": "float", "default": 5.0},
        },
        supports_check_mode=True,
    )
    from ansible.module_utils.dns_state import canonical, fqdn

    checked = []
    try:
        for raw in module.params["records"]:
            if raw.get("state", "present") == "absent":
                continue  # Absence is verified through configuration readback.
            record = canonical(raw)
            for entry in [record, *record["aliases"]]:
                for version, rdtype in [(4, "A"), (6, "AAAA")]:
                    expected = {
                        ip
                        for ip in record["ip"]
                        if ipaddress.ip_address(ip).version == version
                    }
                    if not expected:
                        continue
                    for transport in [dns.query.udp, dns.query.tcp]:
                        query = dns.message.make_query(fqdn(entry) + ".", rdtype)
                        response = transport(
                            query,
                            module.params["server"],
                            timeout=module.params["timeout"],
                        )
                        actual = {
                            str(ipaddress.ip_address(item.address))
                            for rrset in response.answer
                            if rrset.rdtype == dns.rdatatype.from_text(rdtype)
                            for item in rrset
                        }
                        if response.rcode() != dns.rcode.NOERROR or actual != expected:
                            raise ValueError(
                                f"{fqdn(entry)} {rdtype}/{transport.__name__}: expected {sorted(expected)}, got {sorted(actual)}"
                            )
                checked.append(fqdn(entry))
    except Exception as exc:
        module.fail_json(msg=str(exc))
    module.exit_json(changed=False, verified_names=checked)


if __name__ == "__main__":
    main()
