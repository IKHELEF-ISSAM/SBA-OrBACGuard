# SBA-OrBACGuard

**SBA-OrBACGuard** is a policy-driven access-control enforcement module for the **5G Service-Based Architecture (SBA)**.

The 5G Core Network enables dynamic interactions between Network Functions (NFs) through standardized Service-Based Interfaces (SBIs). While this architecture provides flexibility and scalability, enforcing fine-grained authorization policies for NF-to-NF interactions remains challenging.

This project proposes a policy-driven approach for transforming **5G access-control policies into an executable Organization-Based Access Control (OrBAC) policy model** and enforcing the resulting policies through **SBA-OrBACGuard**.

## Key Features

- Policy-driven access control for 5G SBA
- Transformation of 5G access-control policies into **OrBAC policies**
- Fine-grained and context-aware authorization
- Enforcement of NF-to-NF SBA interactions
- Detection and prevention of unauthorized SBA operations
- Integration with a containerized **Open5GS** deployment
- Support for the **indirect SBA communication model**

## Experimental Setup

SBA-OrBACGuard is evaluated in a containerized **Open5GS 5G Core Network**.

The module intercepts SBA interactions between Network Functions and evaluates each operation against the generated OrBAC policies.

## Objective

The main objective of SBA-OrBACGuard is to demonstrate the feasibility of using **OrBAC as an intermediate policy model** for translating 5G security and access-control requirements into enforceable, fine-grained, and context-aware authorization policies for SBA environments.

## Technologies

- **5G Core Network**
- **3GPP Service-Based Architecture (SBA)**
- **Open5GS**
- **OrBAC**
- **Access Control**
- **Policy Enforcement**
- **Docker / Containers**
- **Service-Based Interfaces (SBI)**

## Research Context

This project investigates **policy-driven security for 5G Service-Based Architectures** and provides a basis for further research on:

- Dynamic authorization
- Context-aware access control
- Automated policy generation
- Fine-grained security policies
- Zero-trust security for 5G/6G
- Security of cloud-native mobile networks

## Paper

This repository accompanies the research work on **SBA-OrBACGuard**, which presents the proposed policy transformation and enforcement approach and evaluates it using a containerized Open5GS deployment.

## License

This project is intended for **research and academic purposes**.
