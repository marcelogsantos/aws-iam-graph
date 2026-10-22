# IAM Graph — Deploy em EC2 (via IAM Role, boto3)

## Requisitos
- EC2 com **IAM Role attached** que tenha permissões de leitura IAM:
  ```json
  {
    "Statement": [{
      "Effect": "Allow",
      "Action": ["iam:list*","iam:get*","sts:GetCallerIdentity"],
      "Resource": "*"
    }]
  }
  ```
  (boto3 na EC2 pega as credenciais automaticamente da instance metadata — **zero access keys no disco**)

## Instalação
```bash
# 1) copiar arquivos
sudo mkdir -p /opt/iam-graph /var/www/iam-graph
sudo cp collector.py /opt/iam-graph/
sudo cp site/* /var/www/iam-graph/

# 2) instalar boto3
sudo pip3 install boto3

# 3) testar manualmente
sudo python3 /opt/iam-graph/collector.py /var/www/iam-graph

# 4) registrar serviço (roda diário às 07:00)
sudo cp iam-graph-collector.service /etc/systemd/system/
sudo cp iam-graph-collector.timer /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now iam-graph-collector.timer

# 5) servir web (nginx, apache, ou python http.server)
sudo ln -sf /var/www/iam-graph /var/www/html/iam-graph
# ou num nginx dedicado na porta 8082
```

## Com resposta em tempo real (S3 + CloudFront)
Alternativa: collector escreve no S3 e CloudFront serve o site — escala pra multi-conta, via facts:
```bash
aws s3 cp site/ s3://SEU-BUCKET-iam-graph/ --recursive --exclude "*" --include "index.html"
aws s3 cp /var/www/iam-graph/graph.json s3://SEU-BUCKET-iam-graph/graph.json --metadata-directive REPLACE --content-type application/json
```

## Forecast de execução
- 1º colisão: ~5 segundos (37 roles)
- Refresh diário: idem (escalada pra novas roles é automática)
