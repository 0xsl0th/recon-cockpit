"""Render the existing proposal locally; never submit, publish or fetch assets.

Documentation-only tool. Uses prepared host Python with Markdown, BeautifulSoup,
WeasyPrint and Graphviz; these are not application dependencies. See checkpoint.
"""

import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
import textwrap

import bs4
from bs4 import BeautifulSoup
import markdown
import weasyprint


ROOT = Path(__file__).resolve().parents[1]
PROPOSAL = ROOT / "docs/competition-proposal.md"
STYLE = ROOT / "docs/submission-print.css"
EMAIL = ROOT / "docs/submission-email.txt"
PDF_NAME = "recon-cockpit-propuesta-20260930.pdf"
REPOSITORY = "https://github.com/0xsl0th/recon-cockpit"


def digest(data):
    return hashlib.sha256(data).hexdigest()


def diagram(mermaid):
    """Render only the existing diagram's simple node/edge syntax, fail on drift."""
    nodes, edges = {}, []

    def node(token):
        match = re.fullmatch(r"([A-Z]+)(?:\[([^\[\]]+)\])?", token.strip())
        if not match:
            raise ValueError("Unsupported diagram node")
        key, label = match.groups()
        if label is not None:
            if key in nodes and nodes[key] != label:
                raise ValueError("Conflicting diagram label")
            nodes[key] = label
        return key

    lines = mermaid.strip().splitlines()
    if lines.pop(0).strip() != "flowchart TD":
        raise ValueError("Unsupported diagram direction")
    for line in lines:
        match = re.fullmatch(r"\s*(.*?)\s*-->(?:\|([^|]+)\|)?\s*(.*?)\s*", line)
        if not match:
            raise ValueError("Unsupported diagram edge")
        source, label, target = match.groups()
        edges.append((node(source), node(target), label or ""))
    if any(a not in nodes or b not in nodes for a, b, _ in edges):
        raise ValueError("Undefined diagram node")

    quote = lambda value: json.dumps(value, ensure_ascii=False)
    wrap = lambda value, width: "\n".join(textwrap.wrap(value, width=width))
    dot = ["digraph architecture {", 'graph [rankdir=TB, bgcolor="transparent", '
           'pad="0.15", nodesep="0.32", ranksep="0.4", splines=polyline];',
           'node [shape=box, style="rounded,filled", fontname="DejaVu Sans", '
           'fontsize=12, color="#53758a", fillcolor="#edf4f7", margin="0.15,0.1"];',
           'edge [fontname="DejaVu Sans", fontsize=10, color="#53758a", '
           'fontcolor="#233e50", arrowsize=0.7];']
    for key, label in nodes.items():
        dot.append(f"{key} [label={quote(wrap(label, 24))}];")
    for source, target, label in edges:
        dot.append(f"{source} -> {target} [label={quote(wrap(label, 23))}];")
    dot.append("}")
    result = subprocess.run(["dot", "-Tsvg"], input="\n".join(dot), text=True,
                            capture_output=True, check=True)
    svg = result.stdout[result.stdout.index("<svg"):]
    return svg, {"nodes": nodes, "edges": edges}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--revision", required=True, help="Full proposal source commit")
    parser.add_argument("--output", required=True, type=Path, help="New local draft directory")
    args = parser.parse_args()
    if not re.fullmatch(r"[0-9a-f]{40}", args.revision):
        parser.error("Use the full source commit hash")
    source = PROPOSAL.read_bytes()
    expected = subprocess.check_output(
        ["git", "show", f"{args.revision}:docs/competition-proposal.md"], cwd=ROOT)
    if source != expected:
        parser.error("Proposal bytes differ from the selected source revision")
    email = EMAIL.read_bytes()
    style = STYLE.read_bytes()
    output = args.output.resolve()
    output.mkdir(mode=0o700, parents=False, exist_ok=False)

    md = source.decode("utf-8")
    blocks = re.findall(r"```mermaid\n(.*?)```", md, re.S)
    if len(blocks) != 1:
        raise ValueError("Expected exactly one architecture diagram")
    svg, graph = diagram(blocks[0])
    md = md.replace("```mermaid\n" + blocks[0] + "```", '<div id="architecture"></div>')
    soup = BeautifulSoup(markdown.markdown(md, extensions=["tables", "fenced_code"]), "html.parser")
    for anchor in soup.find_all("a", href=True):
        target = anchor["href"]
        if target.startswith("https://"):
            continue
        path, _, fragment = target.partition("#")
        local = (PROPOSAL.parent / path).resolve()
        relative = local.relative_to(ROOT)
        if not local.is_file():
            raise ValueError("Missing document link")
        anchor["href"] = f"{REPOSITORY}/blob/{args.revision}/{relative.as_posix()}"
        if fragment:
            anchor["href"] += "#" + fragment

    # The existing heading, introduction and vector diagram share a landscape page.
    marker = soup.find(id="architecture")
    heading = marker.find_previous("h2")
    section = soup.new_tag("section", attrs={"class": "architecture-page"})
    heading.insert_before(section)
    current = heading
    while current is not marker:
        following = current.next_sibling
        section.append(current.extract())
        current = following
    figure = soup.new_tag("figure")
    figure.append(BeautifulSoup(svg, "html.parser"))
    section.append(figure)
    marker.decompose()

    html = '<!doctype html><html lang="es"><head><meta charset="utf-8">'
    html += '<title>Recon Cockpit — propuesta de concurso (borrador)</title>'
    html += '<meta name="author" content="Enrique Folte">'
    html += '<style>' + style.decode("utf-8") + '</style></head><body>' + str(soup) + '</body></html>'
    denied_fetches = []

    def reject_fetch(url, *unused, **kwargs):
        denied_fetches.append(url)
        raise ValueError("External assets are disabled in the proposal renderer")

    document = weasyprint.HTML(string=html, url_fetcher=reject_fetch).render()
    document.write_pdf(output / PDF_NAME)
    if denied_fetches:
        raise ValueError("Document attempted to retrieve an asset")
    (output / "proposal.html").write_text(html, encoding="utf-8")
    (output / "architecture.svg").write_text(svg, encoding="utf-8")
    (output / "submission-email.txt").write_bytes(email)
    (output / "proposal-source.md").write_bytes(source)
    refs = {
        "proposal": f"{REPOSITORY}/blob/{args.revision}/docs/competition-proposal.md",
        "evidence_and_operator_record": f"{REPOSITORY}/blob/{args.revision}/docs/verification.md#r6-offline-operator-rehearsal--30-september-2026",
        "demo_runbook": f"{REPOSITORY}/blob/{args.revision}/docs/offline-release-evidence.md",
        "offline_comparison": f"{REPOSITORY}/blob/{args.revision}/docs/planning-evaluation.md",
    }
    notes = "BORRADOR LOCAL — NO ENVIADO — NO PUBLICADO\n\n"
    notes += f"Adjunto propuesto para revisión: {PDF_NAME}\n"
    notes += "El correo sigue sin enviar. Revise el PDF y el mensaje antes de autorizar un envío.\n"
    notes += "El resto de los archivos documenta esta exportación local; no son adjuntos propuestos.\n\n"
    notes += "Referencias a la revisión de fuente del documento:\n"
    notes += "".join(f"- {name}: {url}\n" for name, url in refs.items())
    notes += "\nEvidencia privada existente (no adjunta ni publicada):\n"
    notes += ".secure-agent/offline-release-evidence-20260930-final/report.md\n"
    notes += "Manifest SHA-256: 467decaa88ddb2861f8216973961f21dcff722e62a89b4ead46c370ae67f1ad7\n"
    notes += "Fuente de verificación de ese paquete: 070257b455f158eb06301fae143c0704ee02ee30\n"
    notes += "Revisión de ejecución de los ensayos históricos: not_recorded\n"
    notes += "Aceptación humana separada: .secure-agent/r6-operator-20260930-retry-w4xi91nq/operator-review.json\n"
    notes += "La revisión del documento no sustituye la procedencia de los ensayos.\n"
    (output / "review-notes.txt").write_text(notes, encoding="utf-8")
    manifest = {
        "status": "local_unsent_submission_draft", "publication_authorized": False,
        "proposal_source_revision": args.revision, "proposal_source_sha256": digest(source),
        "renderer_sha256": digest(Path(__file__).read_bytes()), "stylesheet_sha256": digest(style),
        "email_draft_sha256": digest(email), "pages": len(document.pages),
        "tools": {"python": sys.version.split()[0], "weasyprint": weasyprint.__version__,
                  "markdown": markdown.__version__, "beautifulsoup": bs4.__version__,
                  "graphviz": subprocess.run(
                      ["dot", "-V"], capture_output=True, text=True, check=True).stderr.strip()},
        "diagram": graph, "references": refs, "asset_fetches": denied_fetches,
        "files": {p.name: {"sha256": digest(p.read_bytes()), "bytes": p.stat().st_size}
                  for p in sorted(output.iterdir()) if p.is_file()},
    }
    (output / "render-manifest.json").write_text(json.dumps(manifest, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"output": str(output), "pages": len(document.pages),
                      "pdf_sha256": manifest["files"][PDF_NAME]["sha256"], "asset_fetches": 0}))


if __name__ == "__main__":
    main()
