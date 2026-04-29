from email import policy
from email.parser import BytesParser
import re
import hashlib
import json


def parse_eml(filepath):
    try:
        with open(filepath, "rb") as f:
            msg = BytesParser(policy=policy.default).parse(f)
        return msg
    except FileNotFoundError:
        print("This file is incorrect.")
        return None


def get_parent_domain(domain):
    parts = domain.split(".")
    if len(parts) >= 3:
        return ".".join(parts[-3:])
    return domain


def check_spoofing(msg):
    from_header = msg.get("From", "")
    return_path = msg.get("Return-Path", "")
    reply_to = msg.get("Reply-To", "")

    if from_header:
        from_domain = from_header.split("@")[1].strip(">")
    else:
        from_domain = ""

    if return_path:
        return_domain = return_path.split("@")[1].strip(">")
    else:
        return_domain = ""

    if reply_to:
        reply_domain = reply_to.split("@")[1].strip(">")
    else:
        reply_domain = ""

    from_parent = get_parent_domain(from_domain)
    return_parent = get_parent_domain(return_domain)
    reply_parent = get_parent_domain(reply_domain)

    if from_parent == return_parent and from_parent == reply_parent:
        return f"✅ MATCH — From: {from_domain} | Return-Path: {return_domain} | Reply-To: {reply_domain}"
    else:
        return f"⚠ MISMATCH — From: {from_domain} | Return-Path: {return_domain} | Reply-To: {reply_domain}"


def is_valid_ip(ip):
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    for part in parts:
        if not part.isdigit():
            return False
        if int(part) < 0 or int(part) > 255:
            return False
    return True


def analyze_received_chain(msg):
    received_headers = msg.get_all("Received", [])
    results = []

    for i, header in enumerate(received_headers):
        ips = re.findall(r"\d+\.\d+\.\d+\.\d+", header)
        ips = [ip for ip in ips if is_valid_ip(ip)]
        results.append({
            "hop": i + 1,
            "header": header.strip(),
            "ips": ips
        })

    return results


def check_auth_results(msg):
    auth_results_headers = msg.get_all("Authentication-Results", [])
    results = []

    for i, header in enumerate(auth_results_headers):
        header_spf = re.findall(r"spf=\w+", header)
        header_dkim = re.findall(r"dkim=\w+", header)
        header_dmarc = re.findall(r"dmarc=\w+", header)

        results.append({
            "spf": header_spf,
            "dkim": header_dkim,
            "dmarc": header_dmarc
        })

    return results


def extract_urls(msg):
    urls = []
    body = msg.get_body(preferencelist=("html",))

    if not body:
        body = msg.get_body(preferencelist=("plain",))

    if body:
        content = body.get_content()
        urls = re.findall(r"https?://[^\s\"'>]+", content)

    # Filtrar URLs irrelevantes
    urls = [u for u in urls if not u.endswith(('.png', '.jpg', '.gif', '.css', '.dtd'))
            and 'w3.org' not in u]

    return urls


def analyze_attachments(msg):
    attachments = []

    for attachment in msg.iter_attachments():
        name = attachment.get_filename()
        content = attachment.get_payload(decode=True)
        hash_md5 = hashlib.md5(content).hexdigest()
        hash_sha256 = hashlib.sha256(content).hexdigest()

        attachments.append({
            "file": name,
            "MD5": hash_md5,
            "SHA256": hash_sha256
        })

    return attachments


def collect_iocs(results, urls, attachments):
    ips = []
    for hop in results:
        for ip in hop["ips"]:
            ips.append(ip)

    hashes = []
    for attachment in attachments:
        hashes.append(attachment["MD5"])
        hashes.append(attachment["SHA256"])

    iocs = {
        "ips": list(set(ips)),
        "urls": list(set(urls)),
        "hashes": hashes
    }

    return iocs


def print_report(spoofing, auth, received, urls, attachments, iocs):
    print("\n" + "=" * 60)
    print("           PHISHING TRIAGE REPORT")
    print("=" * 60)

    print("\n  [SPOOFING CHECK]")
    print(f"  {spoofing}")

    print("\n  [AUTHENTICATION]")
    for result in auth:
        spf = result['spf'][0] if result['spf'] else "not found"
        dkim = result['dkim'][0] if result['dkim'] else "not found"
        dmarc = result['dmarc'][0] if result['dmarc'] else "not found"
        print(f"  {spf} | {dkim} | {dmarc}")

    print("\n  [RECEIVED CHAIN]")
    for hop in received:
        if hop['ips']:
            print(f"  Hop {hop['hop']}: {', '.join(hop['ips'])}")
        else:
            print(f"  Hop {hop['hop']}: no IP found")

    print("\n  [URLs FOUND]")
    if urls:
        unique_urls = list(set(urls))
        domains = {}
        for url in unique_urls:
            domain = url.split("/")[2] if len(url.split("/")) > 2 else url
            if domain not in domains:
                domains[domain] = 0
            domains[domain] += 1

        for domain, count in domains.items():
            print(f"  {domain} — {count} URLs")
        print(f"\n  Total: {len(unique_urls)} unique URLs")
        print("  (Use -o to export full URLs to JSON)")
    else:
        print("  None")

    print("\n  [ATTACHMENTS]")
    if attachments:
        for att in attachments:
            print(f"  {att['file']}")
            print(f"    MD5:    {att['MD5']}")
            print(f"    SHA256: {att['SHA256']}")
    else:
        print("  None")

    print()

    print("\n  [IOCs SUMMARY]")
    print(f"  IPs ({len(iocs['ips'])}):")
    if iocs['ips']:
        for ip in iocs['ips']:
            print(f"    {ip}")
    else:
        print("    None")

    print()

    print(f"  Domains ({len(set(url.split('/')[2] for url in iocs['urls'] if len(url.split('/')) > 2))}):")
    domains = {}
    for url in iocs['urls']:
        domain = url.split("/")[2] if len(url.split("/")) > 2 else url
        if domain not in domains:
            domains[domain] = 0
        domains[domain] += 1
    for domain, count in domains.items():
        print(f"    {domain} ({count})")

    print()

    print(f"  Hashes ({len(iocs['hashes'])}):")
    if iocs['hashes']:
        for h in iocs['hashes']:
            print(f"    {h}")
    else:
        print("    None")

    print("\n" + "=" * 60)


def export_json(data, output_path):
    with open(output_path, "w") as f:
        json.dump(data, f, indent=4)
    print(f"\nReport exported to {output_path}")


def main():
    import argparse

    parser = argparse.ArgumentParser(description="Phishing Email Triage Tool")
    parser.add_argument("eml_file", help="Path to the .eml file")
    parser.add_argument("-o", "--output", help="Export report to JSON", default=None)
    args = parser.parse_args()

    msg = parse_eml(args.eml_file)
    if msg is None:
        return

    spoofing = check_spoofing(msg)
    received = analyze_received_chain(msg)
    auth = check_auth_results(msg)
    urls = extract_urls(msg)
    attachments = analyze_attachments(msg)
    iocs = collect_iocs(received, urls, attachments)

    print_report(spoofing, auth, received, urls, attachments, iocs)

    if args.output:
        data = {
            "spoofing": spoofing,
            "authentication": auth,
            "received_chain": received,
            "urls": urls,
            "attachments": attachments,
            "iocs": iocs
        }
        export_json(data, args.output)


if __name__ == "__main__":
    main()
