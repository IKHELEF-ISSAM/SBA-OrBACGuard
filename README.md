SBA-OrBACGuard — GitHub Description


SBA-OrBACGuard
SBA-OrBACGuard is a policy-driven access-control enforcement module for 5G Service-Based Architecture (SBA). It provides fine-grained and context-aware authorization for interactions between 5G Core Network Functions (NFs).

Overview
The 5G Core Network adopts a Service-Based Architecture (SBA), where Network Functions (NFs) dynamically interact through standardized services exposed via Service-Based Interfaces (SBIs). While this architecture improves flexibility, scalability, and modularity, it also introduces new security challenges, particularly regarding the authorization of NF-to-NF service interactions.

Although 3GPP specifications define security and authorization requirements for SBA communications, translating these requirements into executable and fine-grained access-control policies remains challenging.

SBA-OrBACGuard addresses this challenge by introducing a policy-driven approach that transforms 5G access-control requirements into an executable Organization-Based Access Control (OrBAC) policy model.

Architecture
The proposed approach follows the following workflow:

5G Access-Control Policies
            │
            ▼
   Policy Transformation
            │
            ▼
      OrBAC Policy Model
            │
            ▼
      SBA-OrBACGuard
            │
            ▼
     Authorization Check
            │
       ┌────┴────┐
       ▼         ▼
    Allowed    Denied
       │         │
       ▼         ▼
 SBA Operation  Blocked

SBA-OrBACGuard acts as a Policy Enforcement Point (PEP) for SBA communications. It evaluates incoming NF-to-NF operations against the generated OrBAC policies and prevents unauthorized operations from being executed.

Key Features
5G SBA access control for Network Function-to-Network Function interactions.

Policy-driven authorization based on 5G access-control requirements.

Transformation of 5G authorization policies into an executable OrBAC model.

Fine-grained access control for SBA operations.

Context-aware authorization using OrBAC concepts such as roles, activities, views, contexts, and permissions.

Detection and prevention of unauthorized SBA operations.

Support for containerized 5G Core deployments.

Experimental evaluation using Open5GS and the indirect SBA communication model.

Experimental Environment
The approach is evaluated in a containerized 5G Core Network based on Open5GS.

The experimental setup includes multiple 5G Core Network Functions communicating through the SBA. SBA-OrBACGuard intercepts and evaluates SBA operations before allowing them to reach their intended destination.

                 5G Core Network
                       │
        ┌──────────────┼──────────────┐
        │              │              │
       AMF            SMF            UDM
        │              │              │
        └──────── SBA ─┴──────────────┘
                       │
                       ▼
              SBA-OrBACGuard
                       │
                Authorization
                  Evaluation
                  /        \
                 /          \
             ALLOW          DENY
               │              │
               ▼              ▼
          SBA Operation     Blocked

Main Objective
The main objective of SBA-OrBACGuard is to demonstrate that OrBAC can be used as an intermediate policy model for translating high-level 5G access-control requirements into executable and enforceable authorization policies.

The approach aims to bridge the gap between:

3GPP Security Requirements
            ↓
5G Access-Control Policies
            ↓
      OrBAC Model
            ↓
   Policy Enforcement
            ↓
      SBA Operations

Evaluation
The experimental results demonstrate that SBA-OrBACGuard is able to:

identify unauthorized SBA operations;

prevent unauthorized operations from being executed;

enforce fine-grained access-control policies;

support context-aware authorization decisions.

These results demonstrate the feasibility of using OrBAC as an intermediate access-control model for 5G SBA environments.

Technologies
5G Core Network

3GPP SBA

Open5GS

OrBAC

Access Control

Policy Enforcement

Docker / Containers

Service-Based Interfaces (SBI)

Research Context
SBA-OrBACGuard is designed as a research prototype for investigating fine-grained, policy-driven authorization in 5G Service-Based Architectures.

The project can serve as a basis for further research on:

dynamic access-control policies;

context-aware authorization;

automated policy generation;

intent-based security;

zero-trust security for 5G/6G;

policy enforcement in network slicing and cloud-native mobile networks.
