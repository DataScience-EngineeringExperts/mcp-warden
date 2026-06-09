"""Property-based fuzzing of the guard parser + inspection engine (issue #17).

These suites use ``hypothesis`` to drive construction-based liveness + soundness
properties against the live runtime attack surface: the stdio JSON-RPC framer
(``framing``), the ANSI/control-codepoint scanner+stripper (``res_rules`` /
``res_catalog``), the exfil-domain matcher (``res_net``), and the secret redactor
(``redact``). Run the deep soak with ``make fuzz``.
"""
