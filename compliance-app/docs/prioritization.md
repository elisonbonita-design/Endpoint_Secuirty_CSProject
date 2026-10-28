# Risk-based prioritization

This page explains how the compliance app decides which findings to fix first. It is
written so it can be adapted for Chapter 3 of the paper.

## What gets a score

A **finding** is a stored, non-compliant (or unknown) result for one endpoint, for
example "Minimum password length is below 14 on WS01". Findings are kept in the
`findings` table so the app can track how long they have been open and whether they
came back after being fixed.

Only findings that are **non-compliant** and still open (status `open`, `in_review`
or `fixed_pending`) get a score.

- Findings in state **unknown** are never scored. They are listed separately under
  **Needs data**, because missing data is not proof that a setting is wrong.
- Findings that are `cleared`, `verified` or under an approved `exception` are not
  scored either.

## The formula

```
Score = Severity + Exposure + Asset importance + Time open + Repeat   (limited to 0–100)
```

| Part | Maximum | How the points are given |
|---|---|---|
| **Severity** | 40 | From the requirement the finding is mapped to: critical 40, high 30, medium 20, low 10. A vulnerability without a requirement uses its CVSS score × 4, rounded. Anything else gets 10. |
| **Exposure** | 25 | Other open problems on the **same endpoint** that make this one more dangerous: Microsoft Defender real-time protection off (+15), Windows Firewall off for any profile (+15), the CVE is in the local known-exploited list (+25), and a listening port that is not on the approved list (+10). A finding never gets points for its own condition, so a "Defender off" finding does not get the Defender bonus. |
| **Asset importance** | 20 | From the asset record of the endpoint: it handles client data (+12); its role is team lead or IT admin (+8), or it is a shared kiosk (+4). Agent PCs add 0. |
| **Time open** | 10 | 2 points for each full day since the finding was opened. |
| **Repeat** | 5 | 5 points if the finding has come back at least once after being cleared or verified. |

When a part goes over its maximum, it is cut to the maximum.

### Bands

| Score | Band | Floor-plan colour |
|---|---|---|
| 80–100 | Critical | red, letter **C** |
| 60–79 | High | orange, letter **H** |
| 40–59 | Medium | yellow, letter **M** |
| 0–39 | Low | green, letter **L** |

The list is sorted by score from highest to lowest. When two findings have the same
score, the older one comes first.

### The reason text

Every score comes with a short reason that lists only the parts that added points,
largest first. For example:

> Critical (80): BitLocker protection off – critical requirement (40) + Defender
> real-time protection off on this endpoint (15) + handles client data (12) + open
> 4 days (8) + happened before (5)

The parts of the reason always add up to the score, so a reviewer can check the
number by hand.

## Where the numbers live

Every number above is stored in `config/risk_weights.json` and none is written into
the code. The file has a `"version"` field, which starts at `"1.0"`.

- Each saved score (`risk_scores` table) records the weights version it was computed
  with.
- A new score row is added only when the score, band, reason or weights version
  changes. This means old scores stay traceable after the weights are changed.
- To change a weight, edit the file, raise the version (for example to `"1.1"`) and
  restart the app.

Requirements come from `config/requirements.json`, which also has a `"version"`.

- Each finding stores the catalogue version it was first checked against.
- A Wazuh check counts for a requirement only when its exact SCA policy name and
  check ID are listed under `sca_checks`.
- The CIS check IDs written under `unconfirmed_cis_check_ids` are **not used**. They
  were read from the Wazuh source snapshot (5.1.0-alpha0) and still need to be
  confirmed in the 4.14.8 lab before they are moved into `sca_checks`.

Two optional inputs are local files that are never downloaded by the app:

- `config/approved_ports.json` is the approved listening-port baseline.
- `data/kev_snapshot.json` is a known-exploited CVE list, copied by hand while the lab
  is in setup mode. If the file is missing, the known-exploited rule is skipped.

## When scores are updated

Scores are recomputed:

- every time the fleet is loaded, because loading also syncs the stored findings with
  the latest results;
- right after an asset's "handles client data" or "role" field changes;
- every 5 minutes in the background while the app runs, so "time open" keeps
  increasing.

## How findings change status on their own

| What happens | Result |
|---|---|
| A check fails and has no finding yet | New finding: `open` |
| A check passes before anyone marked the finding fixed (for example Group Policy restored it) | `cleared` |
| A finding marked `fixed_pending` passes in a **later** assessment | `verified`, with `verified_at` set |
| A `cleared` or `verified` finding fails again | Back to `open`; `times_reopened` + 1; time open restarts |

People set `in_review`, `fixed_pending` and (admins only) `exception` in the review panel of
each finding; see [sources.md](sources.md) for the full workflow, roles and data sources.

## The rule that AI only explains

Priority is decided **only** by the rule-based score above. The optional local AI
(Ollama on the lab network) may only write text. It never changes a score, a band, a
finding status or any database value, and its answer is shown under the label
**"AI-generated explanation – check before acting"**.

For one finding, the AI receives only these fields:

- finding title
- source
- requirement title
- severity
- band
- score
- reason text
- days open
- endpoint label
- remediation text

It never receives IP addresses, agent IDs, users, passwords, recovery keys or file
contents. The **Daily summary** sends only counts per band and per floor.

If the AI is off, times out or fails, the app shows the rule-based reason and the
remediation text instead, so the page always works without AI.
