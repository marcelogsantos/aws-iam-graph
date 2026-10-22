#!/usr/bin/env python3
"""Coletor IAM → grafo (roles + policies + trust + risco + mitigacoes).
Roda em EC2 com IAM Role da instância (sem access keys hardcoded) — boto3 detecta automaticamente.
Uso: python3 collector.py [output_dir]
"""
import sys, os, json
import boto3

OUT_DIR = sys.argv[1] if len(sys.argv) > 1 else os.path.join(os.path.dirname(os.path.abspath(__file__)), 'site')
os.makedirs(OUT_DIR, exist_ok=True)

iam = boto3.client('iam')

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

nodes, edges = [], []
def node(id_, label, kind, **extra):
    if not any(n['id'] == id_ for n in nodes):
        nodes.append(dict(id=id_, label=label, kind=kind, **extra))

def mitigations(perms, trustee, tags):
    out = []
    a = perms.get('actions', []); r = perms.get('resources', [])
    if '*' in a:
        out.append({"risco":"Action '*' (todas as ações)",
                    "mitigacao":"Substituir por lista explícita de actions (least privilege). Usar IAM Access Analyzer pra identificar uso real."})
    if any(':' in x and x.split(':',1)[1]=='*' for x in a if ':' in x):
        out.append({"risco":"Service-wide wildcard (ex: s3:*)",
                    "mitigacao":"Restringir às actions específicas usadas pela aplicação."})
    if any(x.startswith('iam:') for x in a):
        out.append({"risco":"Permissões iam:* (escalada de privilégio)",
                    "mitigacao":"Remover iam:CreateRole/PassRole/AttachRolePolicy se não usar; senão permissions boundary + condition."})
    if any(x.startswith('sts:AssumeRole') for x in a):
        out.append({"risco":"sts:AssumeRole sem restrição",
                    "mitigacao":"Limitar com Condition aws:PrincipalArn pra roles específicas."})
    if ':root' in (trustee or ''):
        out.append({"risco":"Trust policy aceita account root",
                    "mitigacao":"Trocar Principal root por ARN exato + Condition aws:SourceAccount + ExternalId."})
    if '*' in r:
        out.append({"risco":"Resource '*' (todos os recursos)",
                    "mitigacao":"Restringir a ARNs específicos (buckets, tabelas, filas) usados."})
    if 'Owner' not in tags or 'CostCenter' not in tags:
        out.append({"risco":"Sem tags de governança (Owner/CostCenter)",
                    "mitigacao":"Adicionar tags Owner, CostCenter, Env — obrigatórias pra rastreabilidade."})
    if not out:
        out.append({"risco":"Sem sinais críticos identificados",
                    "mitigacao":"Manter revisão trimestral. Documentar propósito da role."})
    return out

try:
    ident = iam.get_user()['User']; acct_id = ident['Arn'].split(':')[4]
except Exception:
    acct_id = boto3.client('sts').get_caller_identity()['Account']
node('account', f'Conta AWS {acct_id}', 'account', risk=0)

# Roles
pager = iam.get_paginator('list_roles')
for page in pager.paginate():
    for role in page['Roles']:
        rn = role['RoleName']; nid = f'role:{rn}'
        tags = {t['Key']: t['Value'] for t in role.get('Tags', [])}
        trust = role['AssumeRolePolicyDocument']
        if isinstance(trust, str): trust = json.loads(trust)
        trustees = []
        for st in trust.get('Statement', []):
            p = st.get('Principal', {})
            if 'Service' in p:
                s = p['Service']; trustees.append(s if isinstance(s,str) else ','.join(s))
            elif 'AWS' in p:
                a = p['AWS']; trustees.append(a if isinstance(a,str) else ','.join(a))
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
             attached=attached, mitigations=mitigations(perms, ','.join(set(trustees)), tags))
        edges.append({'from': nid, 'to': 'account', 'label': 'pertence à conta', 'kind': 'membership'})
        for t in sorted(set(trustees)):
            tn = f'svc:{t}'; node(tn, t, 'service', risk=0)
            edges.append({'from': tn, 'to': nid, 'label': 'assume (trust)', 'kind': 'trust'})
        for ap in attached:
            pid = f'pol:{ap}'; node(pid, ap, 'policy', risk=0)
            edges.append({'from': pid, 'to': nid, 'label': 'anexada', 'kind': 'policy'})

# Users
for page in iam.get_paginator('list_users').paginate():
    for u in page['Users']:
        un = u['UserName']; nid = f'user:{un}'
        node(nid, un, 'user', risk=0)
        edges.append({'from': nid, 'to': 'account', 'label': 'usuário', 'kind': 'membership'})

# agrupar roles por serviço de trust
svc_roles = {}
for e in edges:
    if e.get('kind') == 'trust':
        svc_roles.setdefault(e['from'].replace('svc:',''), []).append(e['to'].replace('role:',''))
for n in nodes:
    if n['kind'] == 'service':
        n['trusted_roles'] = sorted(svc_roles.get(n['label'], []))

json.dump({'nodes': nodes, 'edges': edges}, open(f'{OUT_DIR}/graph.json','w'), ensure_ascii=False)
json.dump({'generated_at': time_str if (time_str:=__import__('datetime').datetime.now().isoformat()) else '',
           'account': acct_id, 'roles': len(nodes), 'edges': len(edges)},
          open(f'{OUT_DIR}/meta.json','w'))
print(f'✓ nodes {len(nodes)} | edges {len(edges)} → {OUT_DIR}/graph.json')
