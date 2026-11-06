"""
resolve.py: a recursive resolver built using dnspython
"""

import argparse

import dns.message
import dns.name
import dns.query
import dns.rdata
import dns.rdataclass
import dns.rdatatype

import ipaddress
import dns.exception
import dns.flags
import dns.rcode

# Cache completed DNS lookups
CACHE = {}
# Cache nameserver IP addresses
NS_CACHE = {}
# For debugging
QUERY_COUNT = 0 

FORMATS = (("CNAME", "{alias} is an alias for {name}"),
           ("A", "{name} has address {address}"),
           ("AAAA", "{name} has IPv6 address {address}"),
           ("MX", "{name} mail is handled by {preference} {exchange}"))

ROOT_SERVERS = ("198.41.0.4",
                "199.9.14.201",
                "192.33.4.12",
                "199.7.91.13",
                "192.203.230.10",
                "192.5.5.241",
                "192.112.36.4",
                "198.97.190.53",
                "192.36.148.17",
                "192.58.128.30",
                "193.0.14.129",
                "199.7.83.42",
                "202.12.27.33")


def collect_results(name: str) -> dict:
    """
    This function parses final answers into the proper data structure that
    print_results requires. The main work is done within the `lookup` function.
    """
    full_response = {}
    target_name = dns.name.from_text(name)
    # lookup CNAME
    response = lookup(target_name, dns.rdatatype.CNAME)
    cnames = []
    tmp = name
    for answers in response.answer:
        for answer in answers:
            cnames.append({"name": answer, "alias": tmp})
            tmp = answer
    # lookup A
    response = lookup(target_name, dns.rdatatype.A)
    arecords = []
    for answers in response.answer:
        a_name = answers.name
        for answer in answers:
            if answer.rdtype == 1:  # A record
                arecords.append({"name": a_name, "address": str(answer)})
    # lookup AAAA
    response = lookup(target_name, dns.rdatatype.AAAA)
    aaaarecords = []
    for answers in response.answer:
        aaaa_name = answers.name
        for answer in answers:
            if answer.rdtype == 28:  # AAAA record
                aaaarecords.append({"name": aaaa_name, "address": str(answer)})
    # lookup MX
    response = lookup(target_name, dns.rdatatype.MX)
    mxrecords = []
    for answers in response.answer:
        mx_name = answers.name
        for answer in answers:
            if answer.rdtype == 15:  # MX record
                mxrecords.append({"name": mx_name,
                                  "preference": answer.preference,
                                  "exchange": str(answer.exchange)})

    full_response["CNAME"] = cnames
    full_response["A"] = arecords
    full_response["AAAA"] = aaaarecords
    full_response["MX"] = mxrecords

    return full_response

def get_glue(response):
    """Extract IPv4 nameserver addresses from Additional records."""
    addresses = []

    for rrset in response.additional:
        if rrset.rdtype == dns.rdatatype.A:
            for record in rrset:
                try:
                    ipaddress.IPv4Address(str(record))
                    addresses.append(str(record))
                except ValueError:
                    pass

    return addresses

def get_nameservers(response):
    """Extract nameserver hostnames from Authority records."""
    nameservers = []

    for rrset in response.authority:
        if rrset.rdtype == dns.rdatatype.NS:
            for record in rrset:
                nameservers.append(record.target)

    return nameservers

def lookup(target_name: dns.name.Name,
           qtype: dns.rdata.Rdata) -> dns.message.Message:
    """
    This function uses a recursive resolver to find the relevant answer to the
    query.

    TODO: replace this implementation with one which asks the root servers
    and recurses to find the proper answer.
    """
    key = (target_name.to_text().lower(), qtype)

    # Check completed lookup cache
    if key in CACHE:
        return CACHE[key]

    query = dns.message.make_query(target_name, qtype)
    query.flags &= ~dns.flags.RD

    # Track servers already queried for this lookup
    queried = set()

    # Find the closest cached delegation, if one exists
    servers = ROOT_SERVERS

    best_zone = None

    for zone in NS_CACHE:
        if target_name.is_subdomain(zone):
            if best_zone is None or len(zone.labels) > len(best_zone.labels):
                best_zone = zone

    if best_zone is not None:
        servers = NS_CACHE[best_zone]

    response = None

    # Maximum depth prevents infinite referral loops
    for _ in range(20):

        referral_servers = None

        for server in servers:

            if server in queried:
                continue

            queried.add(server)

            # Debugging: Count the number of queries made
            global QUERY_COUNT
            QUERY_COUNT += 1
            print("DNS query:", server)
            try:
                response = dns.query.udp(
                    query,
                    server,
                    timeout=3
                )
            except Exception:
                continue

            # We received an actual answer
            if response.answer:
                break

            # Domain does not exist
            if response.rcode() == dns.rcode.NXDOMAIN:
                break

            # Look for the next delegation
            nameservers = get_nameservers(response)

            if not nameservers:
                continue

            # First try glue records
            addresses = get_glue(response)

            # If there are no glue records, resolve the NS hostnames
            if not addresses:
                for ns in nameservers:
                    ns_response = lookup(
                        ns,
                        dns.rdatatype.A
                    )

                    for rrset in ns_response.answer:
                        if rrset.rdtype == dns.rdatatype.A:
                            for record in rrset:
                                addresses.append(str(record))

            if addresses:
                # Determine which zone the referral belongs to
                for rrset in response.authority:
                    if rrset.rdtype == dns.rdatatype.NS:
                        NS_CACHE[rrset.name] = addresses

                referral_servers = addresses
                break

        # Stop if we got an answer
        if response is not None and (
            response.answer or
            response.rcode() == dns.rcode.NXDOMAIN
        ):
            break

        # No more servers to query
        if not referral_servers:
            break

        servers = referral_servers

    # Return an empty response rather than crashing
    if response is None:
        response = dns.message.make_response(query)

    # Handle CNAME restarts
    if qtype != dns.rdatatype.CNAME:

        has_requested_type = any(
            rrset.rdtype == qtype
            for rrset in response.answer
        )

        cname_target = None

        for rrset in response.answer:
            if rrset.rdtype == dns.rdatatype.CNAME:
                for record in rrset:
                    cname_target = record.target

        if cname_target is not None and not has_requested_type:
            target_response = lookup(cname_target, qtype)

            response.answer.extend(target_response.answer)
    # Cache completed answer
    CACHE[key] = response

    return response
    # outbound_query = dns.message.make_query(target_name, qtype)
    # response = dns.query.udp(outbound_query, "8.8.8.8", 3)
    # return response


def print_results(results: dict) -> None:
    """
    take the results of a `lookup` and print them to the screen like the host
    program would.
    """

    for rtype, fmt_str in FORMATS:
        for result in results.get(rtype, []):
            print(fmt_str.format(**result))


def main():
    """
    if run from the command line, take args and call
    printresults(lookup(hostname))
    """
    argument_parser = argparse.ArgumentParser()
    argument_parser.add_argument("name", nargs="+",
                                 help="DNS name(s) to look up")
    argument_parser.add_argument("-v", "--verbose",
                                 help="increase output verbosity",
                                 action="store_true")
    program_args = argument_parser.parse_args()
    for a_domain_name in program_args.name:
        print_results(collect_results(a_domain_name))
    # Debugging: Print the total number of queries made
    # print("Total DNS queries:", QUERY_COUNT)

if __name__ == "__main__":
    main()
