# IAM Graph — Visualização de roles AWS como grafo

Ferramenta self-hosted pra mapear roles IAM de uma conta AWS em grafo visual: quem assume quem, quais policies anexadas, e score de risco por role. Feito pro caso de uso que a console da AWS não cobre: leitura executiva e auditoria de identidade em grafo, sem confiar os dados da conta a um SaaS de terceiros.

**Princípio: nenhum dado sai da conta.** O coletor roda na sua infra, escreve um JSON local, e a visualização é uma página estática servida por você.

## Como funciona

```
(conta AWS)                    (coletor)                  (visualização)
IAM API ◄── boto3 ── collector.py ──► site/graph.json ◄── index.html
                                        (graus, risco)      Cytoscape.js
```

O coletor extrai 3 relações:
- **role → política anexada** (managed e inline)
- **role → serviço/principal que assume** (trust policy)
- **usuário → política**

Cada role recebe um **score de risco 0–10** calculado sobre as ações da política:

| Sinal | Peso |
|---|---|
| Action `*` | +4 |
| Service wildcard (`s3:*`) | +2 |
| `iam:*` (escalada de privilégio) | +2 |
| `sts:AssumeRole` sem restrição | +1 |
| Resource `*` | +1 |
| > 30 ações | +1 |

Cada sinal também gera uma **mitigação sugerida**, exibida junto no painel de detalhes.

## Arquivos

| Arquivo | Função |
|---|---|
| `collector.py` | coletor completo (boto3 puro, mitigações incluídas) |
| `site/index.html` | visualizador (Cytoscape.js, filtros, painel de detalhes) |
| `report_pdf.py` | relatório tabular em PDF (reportlab) |
| `ec2-portable/` | versão compacta pra EC2 com systemd timer e instance role |

## Rodando

```bash
pip install boto3

# com credenciais de ambiente ou instance role (nunca hardcode):
export AWS_ACCESS_KEY_ID=... AWS_SECRET_ACCESS_KEY=... AWS_DEFAULT_REGION=us-east-1
python3 collector.py site/

# visualizar:
cd site && python3 -m http.server 8082
# abre http://localhost:8082
```

`site/index.html` busca `graph.json` na mesma pasta — com cache-buster, recarregar (F5) já vai trazer dados novos depois de re-coletar.

## Deploy na EC2 (como serviço)

```bash
sudo cp ec2-portable/collector.py /opt/iam-graph/
sudo cp ec2-portable/site/* /var/www/iam-graph/
sudo cp ec2-portable/iam-graph-collector.{service,timer} /etc/systemd/system/
sudo systemctl enable --now iam-graph-collector.timer   # roda diário 07:00
```

Anexe uma **instance role** com política de leitura IAM:
```json
{"Statement": [{"Effect":"Allow",
  "Action": ["iam:list*","iam:get*","sts:GetCallerIdentity"],
  "Resource": "*"}]}
```
Sem access key no disco, sem credencial em SaaS.

## Segurança do deploy

- O grafo mostra trust policies e permissões da sua conta — **não é material público**. Restrinja o Security Group / exponha via túnel.
- A versão `graph_public.json` é só pra screenshot/publicação: substitui o ID real da conta por `ACCOUNT_ID`.
- O `.gitignore` cuida pra nunca commitar `graph.json` gerado (contém os nomes reais das roles da tua conta).

## Roadmap

- [ ] Recursos como nós (S3, DynamoDB) — plotar o caminho até dado
- [ ] Snapshot histórico — evolução de risco ao longo do tempo
- [ ] Alerta ativo — nova role com risco ≥ 7 notifica na hora
- [ ] Múltiplas contas / organizations
