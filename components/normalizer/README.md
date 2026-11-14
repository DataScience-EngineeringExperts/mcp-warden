# Isolated normalization parser

This component is a one-request, supplied-content worker. It does not retrieve
URLs, use credentials, write files, grant delivery authority, or provide an
in-process fallback. The trusted coordinator must validate its entire output.
The Dockerfile and supervisor provide the separately qualified Linux isolation
boundary; importing this worker directly is only a parser test seam.

Runtime identity is Python 3.12, Unicode 15.0.0 and `pypdf==7.1.0`.
`requirements.lock` independently hash-locks the sole third-party parser wheel.
Install with `pip install --require-hashes --only-binary=:all: -r requirements.lock`.
The immutable image contains `worker.py`, `formats*.py`, and the coordinator's
standalone `normalization_ipc.py` under `/worker`. The entrypoint adds only its
immutable own directory to Python's isolated-mode import path.

The framed protocol accepts exactly one root and emits exactly one success or
input-free `NRM-*` refusal. Frames and aggregate wire bytes are bounded by the
shared IPC module. Nothing is delivered until the full root succeeds.

Supported formats are strict UTF-8 plain text/Markdown, JSON, XML, HTML, CSV,
RFC822/MIME, ZIP and conservative text PDF. MIME can explicitly declare ASCII,
UTF-8 or ISO-8859-1. ZIP members require a supported suffix or PDF/ZIP signature;
conflicting signatures, traversal, duplicate names, directories, links,
encryption, unsupported compression/extra fields/descriptors, unknown members and empty
entries refuse.
Only stored/DEFLATE ZIP compression is supported; all traversal remains in memory.
MIME decodes strict base64/quoted-printable and traverses supported attachments.
JSON rejects duplicate keys/nonfinite constants and recursively inspects supplied
MCP `{mimeType, blob|data|text}` carriers, while retaining their encoded source
and all surrounding keys/metadata. XML rejects DTD/entities. HTML retains hidden
content, attributes, comments and an entity-decoded syntax view; non-void tags
require explicit balanced closing tags under this conservative profile. CSV includes all
fields. Source syntax is retained alongside structured decoded inspection views.
HTML and XML also concatenate decoded character data across tags into a dedicated
inspection segment. JSON adds a depth-first, input-order string-value concatenation
view without inserting keys between values. These additional views reconstruct
split text within one supplied root and consume the same output/map/work budgets;
they do not replace syntax, attribute, comment, key or individual-value evidence.

PDF uses strict pypdf parsing and checks every referenced cross-reference object,
including unreachable objects. It retains textual metadata and UTF-8 decoded
stream syntax, then extracts page text including invisible text. Only no-filter
and bounded DEFLATE streams are accepted. Encryption, image/form XObjects,
embedded fonts, byte strings, object streams, active content, XMP, unsupported
operators/filters, unknown fonts and empty/unexplained pages refuse. Office, OCR,
other archives and arbitrary octet streams are outside the profile. This is a
conservative text-PDF subset; normal PDFs outside it can legitimately refuse.

Every nested parser shares one root ledger. `input_bytes` is the root length;
`expanded_bytes` counts decoded ZIP/MIME/embedded payload and PDF-stream bytes;
`output_bytes` sums inspection UTF-8 bytes; `nodes`, `members`, `spans`, and `work`
are cumulative. `work` charges inspected/decoded bytes, traversal nodes and PDF
operations. `depth` and `combining_run` are high-water marks. `map_bytes` equals
the canonical JSON full segment-list size, including raw and normalized text.
Budgets never reset for members, pages or alternate views. Repeated evidence can
therefore reach the map/output cap before the root input cap.

Inspection text applies NFKC then removes Unicode Cf and C0 controls except
TAB/LF/CR; original extracted text remains in `raw_text` for raw inspection.
Only unchanged UTF-8 root plain text has exact attribution. All other segments
use conservative root byte ranges and explicit page/member/view locators.
Structural completeness describes this finite parser profile, never semantic
extraction completeness. Parser omissions and dependency compromise remain
residual risks; worker evidence stays untrusted and cannot remove taint.

Parser corpus command (on builder):
`PYTHONPATH=src .venv/bin/pytest -q tests/test_normalizer_formats.py`.
Sandbox qualification, coordinator validation, guard parity and final artifact
identity require their separate integration tests.
