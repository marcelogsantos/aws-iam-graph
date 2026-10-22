#!/usr/bin/env python3
"""Gera PDF executivo: Roles AWS — Riscos e Mitigações (pra diretoria)."""
import sys, json, os, datetime
# dependência: pip install reportlab
from reportlab.lib.pagesizes import A4, landscape
from reportlab.lib.units import mm
from reportlab.lib import colors
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.platypus import (SimpleDocTemplate, Table, TableStyle, Paragraph,
                                 Spacer, PageBreak)

g = json.load(open(os.path.join(os.path.dirname(__file__), 'site', 'graph.json')))
roles = [n for n in g['nodes'] if n['kind']=='role']
roles.sort(key=lambda x: -x.get('risk',0))

PDF = os.path.join(os.path.dirname(__file__), 'site', 'relatorio_roles.pdf')
doc = SimpleDocTemplate(PDF, pagesize=landscape(A4), leftMargin=15*mm, rightMargin=15*mm,
                        topMargin=12*mm, bottomMargin=12*mm)
styles = getSampleStyleSheet()
h1 = ParagraphStyle('h1', parent=styles['Title'], fontSize=20, textColor=colors.HexColor('#0b1220'))
sub = ParagraphStyle('sub', parent=styles['Normal'], fontSize=9, textColor=colors.HexColor('#555'))
h2 = ParagraphStyle('h2', parent=styles['Heading2'], fontSize=13, spaceBefore=10, textColor=colors.HexColor('#0b1220'))
body = ParagraphStyle('body', parent=styles['Normal'], fontSize=8.5, leading=11.5)
cell = ParagraphStyle('cell', parent=styles['Normal'], fontSize=7.5, leading=9.5)
cellb = ParagraphStyle('cellb', parent=cell, fontName='Helvetica-Bold')

story = []
now = datetime.datetime.now().strftime('%d/%m/%Y %H:%M')
story.append(Paragraph('IAM Graph — Roles AWS: Riscos & Mitigações', h1))
story.append(Paragraph(f'Relatório executivo gerado em {now} · Conta AWS · Semana de Segurança da Informação', sub))
story.append(Spacer(1, 6*mm))

# Resumo executivo
high = [r for r in roles if r.get('risk',0)>=7]
med = [r for r in roles if 4 <= r.get('risk',0) < 7]
low = [r for r in roles if r.get('risk',0) < 4]
summary = f'''<b>Resumo:</b> {len(roles)} roles analisadas ·
<font color="#c0392b"><b>{len(high)} risco alto</b></font> ·
<font color="#d68910"><b>{len(med)} risco médio</b></font> ·
<font color="#1e8449"><b>{len(low)} risco baixo</b></font>.
Prioridade de remediação: <b>{', '.join(r['label'] for r in high)}</b>.'''
story.append(Paragraph(summary, body))
story.append(Spacer(1, 5*mm))

# Tabela principal
data = [[Paragraph('<b>Role</b>', cellb), Paragraph('<b>Risco</b>', cellb),
         Paragraph('<b>Trust (quem assume)</b>', cellb),
         Paragraph('<b>Riscos identificados</b>', cellb),
         Paragraph('<b>Mitigações recomendadas</b>', cellb),
         Paragraph('<b>Tags</b>', cellb)]]

for r in roles:
    risk = r.get('risk', 0)
    color = '#c0392b' if risk>=7 else '#d68910' if risk>=4 else '#1e8449'
    risks = '<br/>'.join('• ' + m['risco'] for m in r.get('mitigations', []))
    mit   = '<br/>'.join('→ ' + m['mitigacao'] for m in r.get('mitigations', []))
    tags  = '<br/>'.join(f"{k}: {v}" for k,v in (r.get('tags') or {}).items()) or '—'
    data.append([
        Paragraph(r['label'], cellb),
        Paragraph(f'<font color="{color}"><b>{risk}/10</b></font>', cell),
        Paragraph(r.get('trustee','—') or '—', cell),
        Paragraph(risks, cell),
        Paragraph(mit, cell),
        Paragraph(tags, cell),
    ])

tbl = Table(data, colWidths=[42*mm, 14*mm, 42*mm, 60*mm, 78*mm, 24*mm], repeatRows=1)
tbl.setStyle(TableStyle([
    ('BACKGROUND', (0,0), (-1,0), colors.HexColor('#0b1220')),
    ('TEXTCOLOR', (0,0), (-1,0), colors.white),
    ('VALIGN', (0,0), (-1,-1), 'TOP'),
    ('GRID', (0,0), (-1,-1), 0.4, colors.HexColor('#d0d8e4')),
    ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, colors.HexColor('#f4f7fb')]),
    ('LEFTPADDING', (0,0), (-1,-1), 4),
    ('RIGHTPADDING', (0,0), (-1,-1), 4),
]))
story.append(tbl)

doc.build(story)
print('PDF gerado:', PDF, '|', os.path.getsize(PDF)//1024, 'KB')
