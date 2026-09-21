#!/usr/bin/env python3
"""Exercise canonical identities through a disposable, restricted-role local API.

Run only against an isolated database after migrations/runtime-grants, with
IAM_ENVIRONMENT=test and local OTP providers. This creates permanent test data.
Set SILICON_IAM_CANONICAL_SMOKE_URL to its loopback HTTP URL; no real credentials
or external notification providers are used or printed.
"""
import json
import os
import uuid
from urllib.error import HTTPError
from urllib.parse import urlparse
from urllib.request import Request, urlopen

BASE = os.environ['SILICON_IAM_CANONICAL_SMOKE_URL'].rstrip('/')
assert urlparse(BASE).hostname in {'localhost', '127.0.0.1', '::1'}, 'loopback API required'
HANDLE = 'smoke_' + uuid.uuid4().hex[:12].replace('0', 'g')
ORG = 'org_' + uuid.uuid4().hex[:12]


def no_principal_ids(value):
    if isinstance(value, dict):
        assert all(not key.endswith('principal_id') for key in value), value.keys()
        for child in value.values():
            no_principal_ids(child)
    elif isinstance(value, list):
        for child in value:
            no_principal_ids(child)


def request(method, path, data=None, token=None, version=None, expected=200, request_key=None):
    headers = {'Content-Type': 'application/json', 'Idempotency-Key': request_key or str(uuid.uuid4())}
    if token:
        headers['Authorization'] = 'Bearer ' + token
    if version is not None:
        headers['If-Match'] = '"' + str(version) + '"'
    req = Request(BASE + path, data=json.dumps(data).encode() if data is not None else None,
                  method=method, headers=headers)
    try:
        with urlopen(req, timeout=20) as response:
            status, body = response.status, response.read()
    except HTTPError as error:
        status, body = error.code, error.read()
    value = json.loads(body) if body else None
    assert status == expected, (method, path, status,
                                value.get('error', 'unexpected success status') if isinstance(value, dict)
                                else 'unexpected response')
    no_principal_ids(value)
    return value


session = request('POST', '/api/v1/signup/sessions', {}, expected=201)['session_id']
root = '/api/v1/signup/sessions/' + session
phone = '+1415555' + str(uuid.uuid4().int % 10000).zfill(4)
for channel, contact in [('email', {'email': HANDLE + '@example.test'}),
                         ('phone', {'phone_number': phone})]:
    challenge = request('POST', root + '/' + channel, contact, expected=202)
    assert challenge.get('local_otp'), 'isolated local OTP providers required'
    request('POST', root + '/' + channel + '/verify', {'code': challenge['local_otp']})
carbon = request('POST', root + '/complete',
                 {'carbon_id': HANDLE, 'display_name': 'Canonical Smoke', 'timezone': 'UTC'},
                 expected=201)
assert carbon['carbon_id'] == HANDLE
print('PASS canonical Carbon signup')
challenge = request('POST', '/api/v1/login/challenges', {'carbon_id': HANDLE}, expected=201)
tokens = request('POST', '/api/v1/login/challenges/' + challenge['session_id'] + '/verify',
                 {'code': challenge['local_otp']})
assert tokens['actor']['public_id'] == HANDLE
owner_token = tokens['access_token']
profile = request('GET', '/api/v1/me', token=owner_token)
profile = request('PATCH', '/api/v1/me', {'timezone': 'Asia/Kolkata'},
                  owner_token, profile['version'])
assert profile['timezone'] == 'Asia/Kolkata'
refreshed = request('POST', '/api/v1/auth/tokens/refresh', {'refresh_token': tokens['refresh_token']})
assert refreshed['actor']['public_id'] == HANDLE
owner_token = refreshed['access_token']
print('PASS canonical Carbon login, profile timezone, token refresh')
organization = request('POST', '/api/v1/organizations',
                       {'org_id': ORG, 'name': 'Canonical Smoke Organization'}, owner_token,
                       expected=201)
assert organization['owner_membership_id'] == HANDLE + '[' + ORG + ']'
root = '/api/v1/organizations/' + ORG
created = request('POST', root + '/silicons',
                  {'silicon_id': 'chef', 'display_name': 'Chef', 'timezone': 'UTC',
                   'job_description': 'Prepare meals'}, owner_token, expected=201)
silicon = created['silicon']
assert silicon['silicon_id'] == 'chef:' + ORG
assert silicon['job_description'] == 'Prepare meals'
assert 'description' not in silicon and 'job_role' not in silicon
print('PASS organization and canonical Silicon creation')
silicon_tokens = request('POST', '/api/v1/silicon-auth/token',
                         {'silicon_id': silicon['silicon_id'],
                          'silicon_token': created['silicon_token']})
assert silicon_tokens['actor']['public_id'] == silicon['silicon_id']
profile = request('PATCH', root + '/silicons/' + silicon['silicon_id'],
                  {'timezone': 'America/New_York'}, silicon_tokens['access_token'],
                  silicon['version'])
assert profile['timezone'] == 'America/New_York'
readback = request('GET', root + '/silicons/' + silicon['silicon_id'], token=owner_token)
assert readback['timezone'] == 'America/New_York'
listing = request('GET', root + '/silicons?limit=1', token=owner_token)
assert listing['items'][0]['silicon_id'] == silicon['silicon_id']
print('PASS Silicon token login, self timezone update, organization readback/list')
policies = request('GET', root + '/action-policies', token=owner_token)
assert policies['can_manage'] and len(policies['items']) == 14
assert all(not any(row['auto_approve'].values()) for row in policies['items'])
policy_path = root + '/action-policies/membership.job_description.update'
member_path = root + '/members/' + silicon['silicon_id'] + '[' + ORG + ']'
member = request('GET', member_path, token=owner_token)
job_policy = next(row for row in policies['items']
                  if row['action'] == 'membership.job_description.update')
assert job_policy['approval'] == job_policy['defaults']['approval'] == 'none'
direct = request('PUT', member_path + '/job-role',
                 {'job_description': 'Prepare meals without approval'},
                 silicon_tokens['access_token'], member['version'])
assert direct['job_description'] == 'Prepare meals without approval'
assert request('GET', root + '/action-approvals', token=owner_token)['items'] == []
print('PASS Job Description applies directly without default approval')
# Exercise the configurable approval workflow only after explicitly enabling it.
request('PUT', policy_path,
        {'allowed_actors': 'any_member', 'approval': 'admin',
         'auto_approve': {'carbon_ids': [], 'silicon_ids': [], 'tag_ids': []}},
        owner_token, 0)
member = request('GET', member_path, token=owner_token)
change = {'job_description': 'Prepare meals with manual approval'}
retry_key = str(uuid.uuid4())
pending = request('PUT', member_path + '/job-role', change,
                  silicon_tokens['access_token'], member['version'], 428, retry_key)
assert pending['error']['code'] == 'approval_required'
approval_id = pending['error']['details']['approval_request_id']
reviews = request('GET', root + '/action-approvals', token=owner_token)['items']
review = next(row for row in reviews if row['id'] == approval_id)
assert review['request_body'] == change and review['can_decide']
assert review['path'] == member_path + '/job-role'
request('POST', root + '/action-approvals/' + approval_id + '/decisions',
        {'decision': 'approve'}, owner_token, review['version'])
applied = request('PUT', member_path + '/job-role', change,
                  silicon_tokens['access_token'], member['version'], request_key=retry_key)
assert applied['job_description'] == change['job_description']
replay = request('PUT', member_path + '/job-role', change,
                 silicon_tokens['access_token'], member['version'], request_key=retry_key)
assert replay == applied
print('PASS exact manual approval, consumption and idempotent replay')
rule = {'allowed_actors': 'any_member', 'approval': 'admin',
        'auto_approve': {'carbon_ids': [], 'silicon_ids': [silicon['silicon_id']], 'tag_ids': []}}
request('PUT', policy_path, rule, owner_token, 1)
member = request('GET', member_path, token=owner_token)
automatic = request('PUT', member_path + '/job-role',
                    {'job_description': 'Prepare meals automatically'},
                    silicon_tokens['access_token'], member['version'])
assert automatic['job_description'] == 'Prepare meals automatically'
print('PASS owner policy configuration and canonical Silicon automatic approval')
print(json.dumps({'carbon_id': HANDLE, 'silicon_id': silicon['silicon_id'], 'org_id': ORG}))
