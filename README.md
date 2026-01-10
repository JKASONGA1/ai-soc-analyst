# AI-Powered SOC Analyst Assistant

## Overview
This project implements an AI-assisted Security Operations Center (SOC) analyst tool that transforms raw SIEM alerts into structured incident summaries, MITRE ATT&CK mappings, severity classifications, and response recommendations.

The goal is to reduce analyst workload and improve incident response efficiency by automating repetitive analysis tasks using large language models (LLMs).

---

## Problem Statement
SOC analysts frequently face alert fatigue due to high volumes of SIEM alerts. Manual correlation, interpretation, and documentation of incidents consume valuable time and introduce inconsistency.

---

## Solution
This system ingests SIEM alerts (Splunk), correlates related events, and applies AI-driven analysis to produce analyst-ready incident reports.

---

## Architecture (High-Level)

SIEM Alerts (Splunk)
        |
Preprocessing & Correlation
        |
AI Analysis (LLM)
        |
Incident Summary & Response Guidance

---

## Core Features
- SIEM alert ingestion and normalization
- Event correlation by IP, user, and time window
- AI-generated incident summaries
- MITRE ATT&CK technique mapping
- Severity classification
- Recommended response actions

---

## Technology Stack
- Python
- Splunk (SIEM)
- Large Language Model (LLM)
- MITRE ATT&CK Framework

---

## Project Status
In development (MVP)

---

## Disclaimer
This project is for educational and portfolio purposes only.
