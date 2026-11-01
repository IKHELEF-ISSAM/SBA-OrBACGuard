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

This diagram is conceptual; do not interpret it as evidence of inline interception or complete live enforcement in this archive. The original README describes an Open5GS experiment, but deployment assets are absent.

## Conference presentation sequence
1. Motivation and 5G SBA threat model.
2. Policy model and mapping of 5G operations to OrBAC concepts.
3. Prototype processing pipeline and assumptions.
4. Experimental environment (provide actual Open5GS versions and topology).
5. Evaluation scenarios, baseline, metrics and observed results (to be supplied).
6. Limitations, reproducibility and future work.
