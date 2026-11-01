# SBA-OrBACGuard

**Research artifact | Policy-driven access control for the 5G Service-Based Architecture**

SBA-OrBACGuard explores the use of Organization-Based Access Control (OrBAC) to represent and evaluate authorization decisions for interactions between 5G Network Functions (NFs) in the Service-Based Architecture (SBA). The repository includes a Java prototype, an OrBAC policy export, example trace-derived data, and screenshots from an experimental setup.

> **Artifact status:** This is a reorganized research snapshot, not a turnkey reproducible Open5GS deployment. The original archive does not include the external `orbac` Java dependency, the referenced `PCAP_Attack.txt` input, or Open5GS/Docker configuration. No experimental metrics or results have been fabricated.

## Research motivation

The 5G SBA enables NF-to-NF service interactions. Fine-grained authorization may benefit from a policy abstraction that separates organizational roles, activities, and contextual rules from low-level requests. This prototype investigates OrBAC-based policy evaluation of such interactions.

## Repository map

| Location | Contents |
| --- | --- |
| `src/java/` | Original Java prototype (preserved without functional modifications) |
| `policies/orbac/` | Original OrBAC XML policy, renamed with `.xml` extension |
| `experiments/data/` | Example registration, deregistration and token data |
| `experiments/figures/` | Original screenshots |
| `docs/` | Architecture, reproducibility, limitations and original README |
| `deployment/` | Deployment prerequisites and missing components |

## Prototype workflow

1. Read a text-formatted network trace (`PCAP_Attack.txt`, not included).
2. Extract NF registration and deregistration operations and selected service requests.
3. Load the OrBAC policy and evaluate extracted requests through the external `orbac` library.
4. Produce intermediate files and inspect policy enforcement behavior.

See [architecture](docs/ARCHITECTURE.md) and [reproduction guide](docs/REPRODUCIBILITY.md).

## Quick inspection

```bash
python3 -c "import xml.etree.ElementTree as ET; ET.parse('policies/orbac/5g.xml'); print('XML parsed')"
```

The Java file defines `public class OrBacPolicy_Open5GS` but is stored as `SCP_Module.java` in the original archive. For compilation, copy it to `OrBacPolicy_Open5GS.java` and provide the external OrBAC dependency. See the reproduction guide.

## Figures

The supplied figures are illustrative screenshots, not independently verified benchmark results. See `experiments/figures/`.

## Citation and license

If using this artifact, cite the associated paper when its bibliographic details are available. The original repository did not provide a formal license or complete paper metadata; do not assume a redistribution license beyond the permissions granted by the rights holder.

## Provenance

Reorganized from the user-provided `SBA-OrBACGuard-main.zip`; the original README is retained in `docs/ORIGINAL_README.md`. Source code and experimental artifacts are preserved byte-for-byte, except the XML file's path/extension.
"# SBA-OrBACGuard" 
