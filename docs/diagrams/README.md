# Diagrams

* `source/*.mmd` – editable [Mermaid](https://mermaid.js.org) sources (the two ER diagrams are generated from the SQLAlchemy models by `scripts/generate_erd.py`).
* `rendered/*.png|svg` – rendered images used in the PDFs.

Re-render offline:

```bash
cd .tmp/mermaid && npm install mermaid@10.9.1     # once
python scripts/generate_erd.py
python scripts/render_diagrams.py                  # all, or: python scripts/render_diagrams.py 06-class-diagram
```

| File | Diagram |
|---|---|
| 01-system-architecture | System architecture |
| 02-dfd-level-0 / 03-dfd-level-1 | Data-flow diagrams |
| erd-simulator / erd-core | ER diagrams (generated from the real schema) |
| 05-use-case | UML use-case |
| 06-class-diagram | UML class |
| 07-component-diagram | UML component |
| 08-sequence-remediation | UML sequence (preview, apply, verify) |
| 09-activity-remediation | UML activity |
| 10-state-lifecycles | UML state (finding, recommendation, EC2) |
| 11-fake-aws-topology | Fake AWS network topology |
| 12-simulator-workflow | Simulator workflow |
| 13-detection-remediation-workflow | Security detection and remediation workflow |
| 14-whatif-workflow | What-if simulation workflow |
