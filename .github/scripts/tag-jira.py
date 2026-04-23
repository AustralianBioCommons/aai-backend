import os, re, json, urllib.request, urllib.error, base64

base_url = os.environ['JIRA_BASE_URL']
tag = os.environ['RELEASE_TAG']
auth = base64.b64encode(
    f"{os.environ['JIRA_USER_EMAIL']}:{os.environ['JIRA_API_TOKEN']}".encode()
).decode()
headers = {
    'Authorization': f'Basic {auth}',
    'Content-Type': 'application/json',
    'Accept': 'application/json',
}


def jira(method, path, body=None):
    url = f"{base_url}/rest/api/3{path}"
    data = json.dumps(body).encode() if body else None
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req) as r:
            text = r.read()
            return json.loads(text) if text else None
    except urllib.error.HTTPError as e:
        print(f"  WARN {e.code} {method} {path}: {e.read().decode()[:200]}")
        return None


tickets = sorted(set(re.findall(r'AAI-\d+', os.environ['RELEASE_BODY'])))
if not tickets:
    print("No AAI-* tickets found in release notes — nothing to tag.")
    raise SystemExit(0)
print(f"Tickets in {tag}: {', '.join(tickets)}")

project = jira('GET', '/project/AAI')
if not project:
    raise SystemExit("ERROR: could not fetch AAI project from JIRA")

versions = jira('GET', '/project/AAI/versions') or []
existing = next((v for v in versions if v['name'] == tag), None)
if existing:
    version_id = existing['id']
    print(f"Reusing existing JIRA version '{tag}' (id={version_id})")
else:
    created = jira('POST', '/version', {
        'name': tag,
        'projectId': project['id'],
        'released': True,
    })
    if not created:
        raise SystemExit("ERROR: could not create JIRA version")
    version_id = created['id']
    print(f"Created JIRA version '{tag}' (id={version_id})")

for ticket in tickets:
    issue = jira('GET', f'/issue/{ticket}?fields=fixVersions,summary')
    if not issue:
        print(f"  SKIP {ticket}: issue not found or inaccessible")
        continue
    current = issue['fields'].get('fixVersions', [])
    if any(v['id'] == version_id for v in current):
        print(f"  SKIP {ticket}: already tagged with {tag}")
        continue
    jira('PUT', f'/issue/{ticket}', {
        'fields': {'fixVersions': current + [{'id': version_id}]}
    })
    print(f"  DONE {ticket}: {issue['fields'].get('summary', '')[:60]}")

print(f"\nTagged {len(tickets)} ticket(s) with fix version '{tag}'.")
