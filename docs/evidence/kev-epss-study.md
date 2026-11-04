# How low was EPSS before a CVE was added to CISA KEV?

Every CVE CISA added to KEV from 2025-11-02 to 2026-11-02, with its FIRST EPSS score on the day 30, 90 and 180 days before it was added: the score a team would have seen when it accepted the risk.

| Days before KEV | CVEs scored | EPSS below 0.01 | below 0.1 | below 0.5 | median EPSS |
|---|---|---|---|---|---|
| 30 | 124 of 313 | 58 (47%) | 79 (64%) | 95 (77%) | 0.0136 |
| 90 | 90 of 313 | 37 (41%) | 50 (56%) | 65 (72%) | 0.0371 |
| 180 | 71 of 313 | 28 (39%) | 35 (49%) | 47 (66%) | 0.12902 |

A CVE with no score on that day (not yet published or scored) is left out of the percentages.

Sources: CISA KEV catalog version 2026.11.03; FIRST EPSS API (`https://api.first.org/data/v1/epss`, `date=` parameter). Fetched 2026-11-03. Re-run: `python3 scripts/kev_epss_study.py --end 2026-11-02`.
