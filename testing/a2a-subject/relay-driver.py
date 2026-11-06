#!/usr/bin/env python3
"""Configure one already-running fixture registration through ordinary trust APIs.

No task operation is sent here. The boot-owned signing vendor signs the downstream
card under its existing genuine issuer; this adapter has neither private key nor
request/response challenge. The measurement starts only after this command exits.
"""
import argparse
import json
import os
from pathlib import Path
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request


def loopback(value):
    url = urllib.parse.urlsplit(value)
    if url.scheme != 'http' or url.hostname != '127.0.0.1' or url.username or url.password:
        raise ValueError('fixture requires explicit loopback HTTP URL')
    if not url.port or url.fragment:
        raise ValueError('fixture URL requires a port and no fragment')
    return url


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--upstream', required=True)
    parser.add_argument('--downstream', required=True)
    parser.add_argument('--card-url', required=True)
    args = parser.parse_args()
    started = time.monotonic()
    upstream = loopback(args.upstream)
    downstream = loopback(args.downstream)
    card_url = loopback(args.card_url)
    if args.upstream != os.environ['A2A_PROBE_URL']:
        raise ValueError('driver upstream differs from the actual retained fixture endpoint')
    if downstream.path not in ('', '/') or downstream.query:
        raise ValueError('downstream must be an origin')
    if downstream.netloc != card_url.netloc:
        raise ValueError('card must be from the actual downstream origin')
    prefix = '/a2a/agents/'
    if not upstream.path.startswith(prefix):
        raise ValueError('upstream must be the actual fronted registration endpoint')
    name = upstream.path[len(prefix):]
    if not name or '/' in name or '%' in name or upstream.query:
        raise ValueError('expected one literal registration name')
    admin = os.environ['A2A_RELAY_ADMIN_BASE'].rstrip('/')
    loopback(admin)
    loopback(os.environ['A2A_RELAY_VENDOR_URL'])
    directory = Path(os.environ['A2A_RELAY_SUBJECT_DIR']).resolve(strict=True)
    evidence = directory / 'relay-driver-evidence'
    evidence.mkdir(mode=0o700)
    route = directory / 'relay-route.json'
    if route.exists() or route.is_symlink():
        raise ValueError('relay route already configured; use a fresh fixture')

    def request(label, method, url, token=None, body=None):
        remaining = 17.0 - (time.monotonic() - started)
        if remaining <= 0:
            raise TimeoutError('relay configuration deadline exceeded')
        headers = {'content-type': 'application/json'}
        if token:
            headers['authorization'] = 'Bearer ' + token
        req = urllib.request.Request(url, method=method, headers=headers,
            data=None if body is None else json.dumps(body).encode())
        try:
            response = urllib.request.urlopen(req, timeout=min(5.0, remaining))
        except urllib.error.HTTPError as exc:
            response = exc
        with response:
            raw = response.read(1024 * 1024 + 1)
            if len(raw) > 1024 * 1024:
                raise ValueError('configuration response exceeds one MiB')
            (evidence / (label + '.json')).write_bytes(raw)
            if not 200 <= response.status < 300:
                raise ValueError(f'{label} refused with HTTP {response.status}')
        return json.loads(raw)

    actual_card = request('downstream-card', 'GET', args.card_url)
    if not isinstance(actual_card, dict) or not actual_card.get('name'):
        raise ValueError('downstream did not serve an actual named agent card')
    with tempfile.NamedTemporaryFile(mode='w', dir=directory, prefix='.relay-route-', delete=False) as out:
        temporary = Path(out.name)
        json.dump({'downstream': args.downstream, 'card_url': args.card_url}, out)
    temporary.chmod(0o600)
    os.replace(temporary, route)
    endpoint = admin + '/api/v1/admin/agents/' + urllib.parse.quote(name, safe='')
    token = os.environ['A2A_RELAY_ADMIN_TOKEN']
    connected = request('connect', 'POST', endpoint + '/connect', token)
    fingerprint = connected.get('fingerprint')
    if not isinstance(fingerprint, str) or not fingerprint or connected.get('failure'):
        raise ValueError('subject did not verify and report the downstream card fingerprint')
    approved = request('approve', 'POST', endpoint + '/approve', token, {'fingerprint': fingerprint})
    if approved.get('state') != 'approved':
        raise ValueError('subject did not approve the exact observed card')
    # Read-only readiness, never a hidden warm-up task. The host keeps the fronted URL but
    # serves the peer's card name; a stale scenario card cannot satisfy this condition.
    while True:
        served = request('served-card', 'GET', args.upstream, os.environ['A2A_PROBE_TOKEN'])
        if served.get('name') == actual_card['name']:
            break
        if time.monotonic() - started >= 16.5:
            raise TimeoutError('subject has not published the newly approved peer card')
        time.sleep(0.1)
    (evidence / 'configured.json').write_text(json.dumps({
        'upstream': args.upstream, 'downstream': args.downstream, 'card_url': args.card_url,
        'fingerprint': fingerprint, 'state': approved['state'],
        'scope': 'normal connect/approve only; no task traffic or challenge supplied',
    }, indent=2))


if __name__ == '__main__':
    main()
