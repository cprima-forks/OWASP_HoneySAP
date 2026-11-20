# fixture-bapi branch (alpha / proof of value)

Local changes to `honeysap/services/gateway/gateway.py` so the RFC gateway can serve canned BAPI
answers to an SAP .NET Connector (NCo 3.1.0.42, as bundled in UiPath.SAP.BAPI.Activities 3.0.4).
Base: upstream commit `434b6fd`. Licence: GPLv2, unchanged. Every change is marked `LOCAL PATCH (not upstream)`.

## What changed
1. `RFC_FUNCTION_SEARCH(RFC_METADATA_GET)` is answered by closing the connection, so NCo falls back to
   `RFC_GET_FUNCTION_INTERFACE` + `DDIF_FIELDINFO_GET`.
2. `BAPI_MONITOR_GETLIST` returns rows from a CSV (profile option `bapilist_fixture`, columns `ABAPNAME;BAPI_TEXT`).
3. Any function module listed in a second CSV (profile option `results_fixture`, columns `BAPINAME;PARAMETER;VALUE`)
   returns those values as text outputs, cut or blank-padded to the length the RFM catalog declares.
4. In NUC mode the DFIES running offset is kept in UC bytes (the table rows are UTF-16).

Both CSV files are read on every call, so edits apply without a restart. Function interfaces still come from
`rfm_catalog` / `ddic_catalog` as in upstream.

## Checked
- NCo acceptance test: connect, read `BAPI_MONITOR_GETLIST` rows by field name, set an input, call
  `BAPI_COMPANYCODE_GETDETAIL`, get `COMPANYNAME = 'Fixture Company AG'`.
- UiPath Studio Test Connection, the Configure BAPI wizard, and `uip rpa run` of a workflow with one BAPI call.

## Not checked
- Missing or unreadable fixture files (the error paths are written, never run).
- Outputs that are not text, structures, tables other than `BAPILIST`, the `RETURN` table.
- Other NCo versions, and any SAP client other than NCo.
- The byte-offset change was tried only with the `BAPIMONSTR` structure.

## Limits
- Only the `BAPILIST` layout (CHAR30 + CHAR80) is supported by the list serializer.
- Studio decides once per process whether to use the round-trip metadata call: restart Studio after changing
  gateway behaviour.
