# fixture-bapi branch (alpha / proof of value)

Local changes so the RFC gateway can serve canned BAPI answers to an SAP .NET Connector (NCo 3.1.0.42, as
bundled in UiPath.SAP.BAPI.Activities 3.0.4). Base: upstream commit `434b6fd`. Licence: GPLv2, unchanged.
Every change is marked `LOCAL PATCH (not upstream)`.

## What changed
1. `RFC_FUNCTION_SEARCH(RFC_METADATA_GET)` is answered by closing the connection, so NCo falls back to
   `RFC_GET_FUNCTION_INTERFACE` + `DDIF_FIELDINFO_GET`.
2. Profile option `bapi_fixtures`: a data folder in the format of
   [cpmf-bapi-fixtures](https://github.com/cprima-forge/cpmf-emulator-bapi) (`functions/*.yaml` signatures,
   `fixtures/*.yaml|*.jsonl` canned answers). Install with the `bapi` extra.
   - On every RFC call the folder is checked for changes. Changed or new files are loaded and merged over
     the CSV catalogs (`rfm_catalog`, `ddic_catalog`), so new functions and new cases are served without a
     restart. A broken file keeps the last good state; the problem is logged.
   - A call to a function in the folder is answered with the matching case: cases with `when` (compared
     with the call's input values) first, then the default case.
   - Code: `honeysap/services/gateway/bapi_fixtures.py`, wired in `gateway.py`.
3. In NUC mode the DFIES running offset is kept in UC bytes (the table rows are UTF-16).

Functions from the folder are announced without basXML support (`REMOTE_BASXML_SUPPORTED` blank), so NCo
sends classic requests whose input values can be read.

## Checked
- NCo acceptance test (`BAPI_MONITOR_GETLIST` rows by field name, `BAPI_COMPANYCODE_GETDETAIL` output).
- With the gateway running: adding a JSONL case with `when: {COMPANYCODEID: "2000"}` changes the answer for
  2000 only; adding a new function (YAML signature + JSONL case) makes it callable at once.
- UiPath Studio Test Connection, the Configure BAPI wizard, and `uip rpa run` of a workflow with one BAPI
  call (the wizard was checked before the switch to the data folder).

## Not checked
- Exports that are not character-like (INT4) or structures (not tables): skipped, logged as errors.
- Inputs that are not character-like, structure inputs, input tables: not matched.
- More than one table in one answer (the table index is the parameter's position among the tables).
- Other NCo versions, and any SAP client other than NCo.
- The byte-offset change was tried only with the `BAPIMONSTR` structure.

## Limits
- Studio decides once per process whether to use the round-trip metadata call: restart Studio after changing
  gateway behaviour. NCo also caches function signatures per process.
