from __future__ import annotations

import xml.etree.ElementTree as ET

from collectors.arxiv_cs_cr.collector import NS, normalize


SAMPLE_ENTRY = """
<entry xmlns="http://www.w3.org/2005/Atom" xmlns:arxiv="http://arxiv.org/schemas/atom">
  <id>http://arxiv.org/abs/2605.13764v1</id>
  <title>VectorSmuggle: Steganographic Exfiltration in Embedding Stores</title>
  <updated>2026-05-13T16:44:20Z</updated>
  <link href="https://arxiv.org/abs/2605.13764v1" rel="alternate" type="text/html"/>
  <link href="https://arxiv.org/pdf/2605.13764v1" rel="related" type="application/pdf" title="pdf"/>
  <summary>Modern retrieval-augmented generation systems convert sensitive content into embeddings.</summary>
  <category term="cs.CR" scheme="http://arxiv.org/schemas/atom"/>
  <category term="cs.IR" scheme="http://arxiv.org/schemas/atom"/>
  <published>2026-05-13T16:44:20Z</published>
  <arxiv:comment>47 pages, 3 figures.</arxiv:comment>
  <arxiv:primary_category term="cs.CR"/>
  <author><name>Jascha Wanger</name></author>
  <arxiv:doi>10.5281/zenodo.20076420</arxiv:doi>
</entry>
"""


def test_normalize_arxiv_atom_entry() -> None:
    entry = ET.fromstring(SAMPLE_ENTRY)

    bulletin = normalize(entry)

    assert bulletin["source"]["source_slug"] == "arxiv_cs_cr"
    assert bulletin["source"]["external_id"] == "2605.13764v1"
    assert bulletin["source"]["origin_url"] == "https://arxiv.org/abs/2605.13764v1"
    assert bulletin["content"]["title"] == "VectorSmuggle: Steganographic Exfiltration in Embedding Stores"
    assert bulletin["content"]["published_at"] == "2026-05-13T16:44:20+00:00"
    assert "category:cs.cr" in bulletin["labels"]
    assert "primary_category:cs.cr" in bulletin["labels"]
    assert bulletin["extra"]["authors"] == ["Jascha Wanger"]
    assert bulletin["extra"]["pdf_url"] == "https://arxiv.org/pdf/2605.13764v1"
    assert bulletin["extra"]["doi"] == "10.5281/zenodo.20076420"
    assert "security-research" in bulletin["topics"]


def test_sample_uses_expected_namespace() -> None:
    entry = ET.fromstring(SAMPLE_ENTRY)
    assert entry.findtext("atom:title", namespaces=NS) is not None
