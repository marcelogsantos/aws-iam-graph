#!/usr/bin/env python3
"""Coletor IAM → grafo de roles AWS (nós + edges + score de risco)."""
import sys, os, json
# Credenciais: sempre via environment (nunca hardcoded) — ou instance role na EC2
# export AWS_ACCESS_KEY_ID=... AWS_SECRET_ACCESS_KEY=... AWS_DEFAULT_REGION=us-east-1
from botocore.session import get_session

iam = get_session().create_client('iam')
raw = json.load(open('/tmp/iam_raw.json'))

nodes, edges = [], []
def node(id_, label, kind, **extra):
    if not any(n['id'] == id_ for n in nodes):
        nodes.append(dict(id=id_, label=label, kind=kind, **extra))

def parse_policy_doc(doc):
    if isinstance(doc, str):
        doc = json.loads(doc)
    actions, resources = set(), set()
    for st in doc.get('Statement', []):
        if isinstance(st, dict) and st.get('Effect') == 'Allow':
            a = st.get('Action', [])
            if isinstance(a, str): a = [a]
            actions.update(a)
            r = st.get('Resource', [])
            if isinstance(r, str): r = [r]
            resources.update(r)
    return {'actions': list(actions), 'resources': list(resources)}

def risk_score(perms):
    a, r = perms.get('actions', []), perms.get('resources', [])
    s = 0
    if '*' in a: s += 4
    if any(':' in x and x.split(':', 1)[1] == '*' for x in a): s += 2
    if any(x.startswith('iam:') for x in a): s += 2
    if any(x.startswith('sts:Assume') for x in a): s += 1
    if '*' in r: s += 1
    if len(a) > 30: s += 1
    return min(10, s)

# conta
try:
    ident = iam.get_user()['User']
    acct_id = ident['Arn'].split(':')[4]
except Exception:
    acct_id = 'ACCOUNT_ID'  # fallback se get_user falhar
node('account', f'Conta AWS {acct_id}', 'account', risk=0)

# ROLES
for role in raw['roles']:
    rn = role['RoleName']
    nid = f'role:{rn}'
    tags = {t['Key']: t['Value'] for t in role.get('Tags', [])}
    trust = role['AssumeRolePolicyDocument']
    if isinstance(trust, str): trust = json.loads(trust)
    trustees = []
    for st in trust.get('Statement', []):
        p = st.get('Principal', {})
        if 'Service' in p:
            s = p['Service']
            trustees.append(s if isinstance(s, str) else ','.join(s))
        elif 'AWS' in p:
            a = p['AWS']
            trustees.append(a if isinstance(a, str) else ','.join(a))
    perms = {'actions': [], 'resources': []}
    try:
        for pn in iam.list_role_policies(RoleName=rn)['PolicyNames']:
            doc = iam.get_role_policy(RoleName=rn, PolicyName=pn)['PolicyDocument']
            pp = parse_policy_doc(doc)
            perms['actions'] += pp['actions']; perms['resources'] += pp['resources']
    except Exception: pass
    attached = []
    try:
        for ap in iam.list_attached_role_policies(RoleName=rn)['AttachedPolicies']:
            attached.append(ap['PolicyName'])
            try:
                dv = iam.get_policy(PolicyArn=ap['PolicyArn'])['Policy']['DefaultVersionId']
                doc = iam.get_policy_version(PolicyArn=ap['PolicyArn'], VersionId=dv)['PolicyVersion']['Document']
                pp = parse_policy_doc(doc)
                perms['actions'] += pp['actions']; perms['resources'] += pp['resources']
            except Exception: pass
    except Exception: pass
    perms['actions'] = sorted(set(perms['actions']))
    perms['resources'] = sorted(set(perms['resources']))
    score = risk_score(perms)
    node(nid, rn, 'role', risk=score, tags=tags,
         trustee=', '.join(sorted(set(trustees))),
         actions=perms['actions'][:60], resources=perms['resources'][:20],
         attached=attached)
    edges.append({'from': nid, 'to': 'account', 'label': 'pertence à conta', 'kind': 'membership'})
    for t in sorted(set(trustees)):
        tn = f'svc:{t}'
        node(tn, t, 'service', risk=0)
        edges.append({'from': tn, 'to': nid, 'label': 'assume (trust)', 'kind': 'trust'})
    for ap in attached:
        pid = f'pol:{ap}'
        node(pid, ap, 'policy', risk=0)
        edges.append({'from': pid, 'to': nid, 'label': 'anexada', 'kind': 'policy'})

# USERS
for u in raw['users']:
    un = u['UserName']
    nid = f'user:{un}'
    node(nid, un, 'user', risk=0)
    edges.append({'from': nid, 'to': 'account', 'label': 'usuário', 'kind': 'membership'})
    try:
        for ap in iam.list_attached_user_policies(UserName=un)['AttachedPolicies']:
            pid = f'pol:{ap["PolicyName"]}'
            node(pid, ap['PolicyName'], 'policy', risk=0)
            edges.append({'from': pid, 'to': nid, 'label': 'anexada', 'kind': 'policy'})
    except Exception: pass

json.dump({'nodes': nodes, 'edges': edges}, open('/tmp/iam_graph.json', 'w'))
print(f'nodes: {len(nodes)} | edges: {len(edges)}')
roles_r = sorted([(n['label'], n.get('risk', 0)) for n in nodes if n['kind'] == 'role'], key=lambda x: -x[1])
print('top risk:')
for lbl, r_ in roles_r[:8]:
    print(f'  {r_:2d}  {lbl}')
