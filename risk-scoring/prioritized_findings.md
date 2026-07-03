# Prioritized Findings

| Rank | Finding ID | Endpoint | CVE | Final score |
| ---: | --- | --- | --- | ---: |
| 1 | F-008 | win-dev-01 | CVE-2023-23397 | 94.88 |
| 2 | F-003 | win-legacy-01 | CVE-2021-40444 | 86.22 |
| 3 | F-006 | mac-user-01 | CVE-2023-4863 | 81.18 |
| 4 | F-009 | win-user-01 | CVE-2024-21412 | 80.26 |
| 5 | F-010 | mac-user-01 | CVE-2021-30860 | 72.98 |
| 6 | F-007 | ubuntu-dev-01 | CVE-2024-6387 | 46.66 |
| 7 | F-005 | ubuntu-dev-01 | CVE-2024-3094 | 38.60 |
| 8 | F-002 | win-dev-01 | CVE-2022-29072 | 37.28 |
| 9 | F-001 | win-user-01 | CVE-2022-29072 | 30.68 |
| 10 | F-004 | win-legacy-01 | CVE-2020-0796 | 27.12 |

## Factor Breakdown

### 1. F-008 - win-dev-01 - CVE-2023-23397

Context note: credential theft from mail clients is worse on a box with repo access

| Line item | Normalized value | Weight | Contribution |
| --- | ---: | ---: | ---: |
| cvss | 0.980 | 16.0 | 15.68 |
| epss | 0.960 | 20.0 | 19.20 |
| kev | 1.000 | 22.0 | 22.00 |
| exploit_available | 1.000 | 14.0 | 14.00 |
| arcane_context | 0.860 | 10.0 | 8.60 |
| criticality | 1.000 | 7.0 | 7.00 |
| exposure | 0.800 | 6.0 | 4.80 |
| persona_risk | 0.720 | 5.0 | 3.60 |
| base_score |  |  | 94.88 |
| legacy_multiplier | x1.00 |  | 94.88 |
| controls |  |  | -0.00 |
| final_score |  |  | 94.88 |

### 2. F-003 - win-legacy-01 - CVE-2021-40444

Context note: legacy browser-adjacent handling still makes this a practical foothold

| Line item | Normalized value | Weight | Contribution |
| --- | ---: | ---: | ---: |
| cvss | 0.880 | 16.0 | 14.08 |
| epss | 0.860 | 20.0 | 17.20 |
| kev | 1.000 | 22.0 | 22.00 |
| exploit_available | 1.000 | 14.0 | 14.00 |
| arcane_context | 0.820 | 10.0 | 8.20 |
| criticality | 1.000 | 7.0 | 7.00 |
| exposure | 1.000 | 6.0 | 6.00 |
| persona_risk | 0.580 | 5.0 | 2.90 |
| base_score |  |  | 91.38 |
| legacy_multiplier | x1.25 |  | 114.22 |
| control:network_isolation |  |  | -10.00 |
| control:inbound_restriction |  |  | -7.00 |
| control:rdp_disabled_default |  |  | -6.00 |
| control:reduced_local_admin |  |  | -5.00 |
| final_score |  |  | 86.22 |

### 3. F-006 - mac-user-01 - CVE-2023-4863

Context note: image parsing bugs land where creative users actually spend the day

| Line item | Normalized value | Weight | Contribution |
| --- | ---: | ---: | ---: |
| cvss | 0.880 | 16.0 | 14.08 |
| epss | 0.740 | 20.0 | 14.80 |
| kev | 1.000 | 22.0 | 22.00 |
| exploit_available | 1.000 | 14.0 | 14.00 |
| arcane_context | 0.680 | 10.0 | 6.80 |
| criticality | 0.600 | 7.0 | 4.20 |
| exposure | 0.500 | 6.0 | 3.00 |
| persona_risk | 0.460 | 5.0 | 2.30 |
| base_score |  |  | 81.18 |
| legacy_multiplier | x1.00 |  | 81.18 |
| controls |  |  | -0.00 |
| final_score |  |  | 81.18 |

### 4. F-009 - win-user-01 - CVE-2024-21412

Context note: user-click path is boring until SmartScreen is the thing that fails

| Line item | Normalized value | Weight | Contribution |
| --- | ---: | ---: | ---: |
| cvss | 0.810 | 16.0 | 12.96 |
| epss | 0.730 | 20.0 | 14.60 |
| kev | 1.000 | 22.0 | 22.00 |
| exploit_available | 1.000 | 14.0 | 14.00 |
| arcane_context | 0.790 | 10.0 | 7.90 |
| criticality | 0.600 | 7.0 | 4.20 |
| exposure | 0.500 | 6.0 | 3.00 |
| persona_risk | 0.320 | 5.0 | 1.60 |
| base_score |  |  | 80.26 |
| legacy_multiplier | x1.00 |  | 80.26 |
| controls |  |  | -0.00 |
| final_score |  |  | 80.26 |

### 5. F-010 - mac-user-01 - CVE-2021-30860

Context note: old but still a useful reminder that document preview chains age badly

| Line item | Normalized value | Weight | Contribution |
| --- | ---: | ---: | ---: |
| cvss | 0.780 | 16.0 | 12.48 |
| epss | 0.490 | 20.0 | 9.80 |
| kev | 1.000 | 22.0 | 22.00 |
| exploit_available | 1.000 | 14.0 | 14.00 |
| arcane_context | 0.520 | 10.0 | 5.20 |
| criticality | 0.600 | 7.0 | 4.20 |
| exposure | 0.500 | 6.0 | 3.00 |
| persona_risk | 0.460 | 5.0 | 2.30 |
| base_score |  |  | 72.98 |
| legacy_multiplier | x1.00 |  | 72.98 |
| controls |  |  | -0.00 |
| final_score |  |  | 72.98 |

### 6. F-007 - ubuntu-dev-01 - CVE-2024-6387

Context note: SSH exposure makes the proof of concept worth watching

| Line item | Normalized value | Weight | Contribution |
| --- | ---: | ---: | ---: |
| cvss | 0.810 | 16.0 | 12.96 |
| epss | 0.320 | 20.0 | 6.40 |
| kev | 0.000 | 22.0 | 0.00 |
| exploit_available | 0.500 | 14.0 | 7.00 |
| arcane_context | 0.470 | 10.0 | 4.70 |
| criticality | 1.000 | 7.0 | 7.00 |
| exposure | 0.800 | 6.0 | 4.80 |
| persona_risk | 0.760 | 5.0 | 3.80 |
| base_score |  |  | 46.66 |
| legacy_multiplier | x1.00 |  | 46.66 |
| controls |  |  | -0.00 |
| final_score |  |  | 46.66 |

### 7. F-005 - ubuntu-dev-01 - CVE-2024-3094

Context note: supply-chain blast radius matters even without broad endpoint exploitation

| Line item | Normalized value | Weight | Contribution |
| --- | ---: | ---: | ---: |
| cvss | 1.000 | 16.0 | 16.00 |
| epss | 0.020 | 20.0 | 0.40 |
| kev | 0.000 | 22.0 | 0.00 |
| exploit_available | 0.000 | 14.0 | 0.00 |
| arcane_context | 0.660 | 10.0 | 6.60 |
| criticality | 1.000 | 7.0 | 7.00 |
| exposure | 0.800 | 6.0 | 4.80 |
| persona_risk | 0.760 | 5.0 | 3.80 |
| base_score |  |  | 38.60 |
| legacy_multiplier | x1.00 |  | 38.60 |
| controls |  |  | -0.00 |
| final_score |  |  | 38.60 |

### 8. F-002 - win-dev-01 - CVE-2022-29072

Context note: real lab finding: 7-Zip 21.07 inventoried by osquery; same CVE and same intel as win-user-01 - only persona/business context differs

| Line item | Normalized value | Weight | Contribution |
| --- | ---: | ---: | ---: |
| cvss | 0.780 | 16.0 | 12.48 |
| epss | 0.020 | 20.0 | 0.40 |
| kev | 0.000 | 22.0 | 0.00 |
| exploit_available | 0.500 | 14.0 | 7.00 |
| arcane_context | 0.200 | 10.0 | 2.00 |
| criticality | 1.000 | 7.0 | 7.00 |
| exposure | 0.800 | 6.0 | 4.80 |
| persona_risk | 0.720 | 5.0 | 3.60 |
| base_score |  |  | 37.28 |
| legacy_multiplier | x1.00 |  | 37.28 |
| controls |  |  | -0.00 |
| final_score |  |  | 37.28 |

### 9. F-001 - win-user-01 - CVE-2022-29072

Context note: real lab finding: 7-Zip 21.07 inventoried by osquery; local privesc, vendor-disputed, PoC-only, not in KEV, EPSS ~1.5% - Arcane deprioritizes as low-signal

| Line item | Normalized value | Weight | Contribution |
| --- | ---: | ---: | ---: |
| cvss | 0.780 | 16.0 | 12.48 |
| epss | 0.020 | 20.0 | 0.40 |
| kev | 0.000 | 22.0 | 0.00 |
| exploit_available | 0.500 | 14.0 | 7.00 |
| arcane_context | 0.200 | 10.0 | 2.00 |
| criticality | 0.600 | 7.0 | 4.20 |
| exposure | 0.500 | 6.0 | 3.00 |
| persona_risk | 0.320 | 5.0 | 1.60 |
| base_score |  |  | 30.68 |
| legacy_multiplier | x1.00 |  | 30.68 |
| controls |  |  | -0.00 |
| final_score |  |  | 30.68 |

### 10. F-004 - win-legacy-01 - CVE-2020-0796

Context note: scary paper score but the isolated subnet trims the obvious path

| Line item | Normalized value | Weight | Contribution |
| --- | ---: | ---: | ---: |
| cvss | 1.000 | 16.0 | 16.00 |
| epss | 0.080 | 20.0 | 1.60 |
| kev | 0.000 | 22.0 | 0.00 |
| exploit_available | 0.500 | 14.0 | 7.00 |
| arcane_context | 0.360 | 10.0 | 3.60 |
| criticality | 1.000 | 7.0 | 7.00 |
| exposure | 1.000 | 6.0 | 6.00 |
| persona_risk | 0.580 | 5.0 | 2.90 |
| base_score |  |  | 44.10 |
| legacy_multiplier | x1.25 |  | 55.12 |
| control:network_isolation |  |  | -10.00 |
| control:inbound_restriction |  |  | -7.00 |
| control:rdp_disabled_default |  |  | -6.00 |
| control:reduced_local_admin |  |  | -5.00 |
| final_score |  |  | 27.12 |
