# Architecture and research narrative

## Problem
NF-to-NF authorization in the 5G SBA requires rules reflecting operations, roles and potentially context. The OrBAC abstraction models organizational roles, activities and views.

## Available implementation
- `src/java/SCP_Module.java`: trace parsing, extraction of registration/deregistration and GET requests, and calls to OrBAC policy handling.
- `policies/orbac/5g.xml`: policy export containing NF roles and SBA activities.
- `experiments/data/`: example intermediate text outputs.

## Conceptual pipeline

```text
5G SBA trace (text export; not included)
           |
           v
 Java trace parser / request extraction
           |
           v
 Intermediate NF and request records
           |
           v
 OrBAC policy evaluation (external library)
           |
           v
 Authorization / attack-analysis workflow
```

