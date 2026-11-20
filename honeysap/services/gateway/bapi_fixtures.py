# HoneySAP - SAP low-interaction honeypot
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# LOCAL PATCH (not upstream), branch fixture-bapi.

"""Serve function signatures and canned answers from a cpmf-bapi-fixtures data folder.

The data folder (profile option ``bapi_fixtures``) is read by the ``cpmf-bapi-fixtures`` package
(https://github.com/cprima-forge/cpmf-emulator-bapi). On every RFC call the folder is checked for
changes; when something changed, its functions and structures are merged over the CSV catalogs
(``rfm_catalog`` / ``ddic_catalog``), so new or edited files are served without a restart.

Limits: only character-like values (CHAR, NUMC, DATS, TIMS) are sent and matched; INT4 values and
structure-typed exports/imports are skipped with an error in the log. Tables of character-like
structures are sent. Only one table per answer has been tested.
"""

import logging
import struct

logger = logging.getLogger(__name__)

_CHAR_LIKE = frozenset({"CHAR", "NUMC", "DATS", "TIMS"})
_EXID = {"CHAR": "C", "NUMC": "N", "DATS": "D", "TIMS": "T", "INT4": "I"}
_INTTYPE = {"CHAR": "C", "NUMC": "N", "DATS": "D", "TIMS": "T", "INT4": "X"}
_PARAMCLASS = {"import": "I", "export": "E", "changing": "C", "tables": "T"}


def _u16(s):
    return s.encode("utf-16-le")


def _tlv(prev_marker, marker, data):
    return struct.pack("!HHH", prev_marker, marker, len(data)) + data


def rfm_entries(catalog):
    """Function signatures in the shape of load_rfm_catalog()."""
    out = {}
    for fn in catalog.functions.values():
        params = []
        for pos, p in enumerate(fn.parameters, 1):
            if p.scalar is not None:
                exid, tabname, intlength = _EXID[p.scalar.abap], "", p.scalar.byte_length
            else:
                exid, tabname = "u", p.structure
                intlength = catalog.structures[p.structure].byte_length
            params.append({
                "paramclass": _PARAMCLASS[p.kind], "parameter": p.name, "tabname": tabname,
                "fieldname": "", "exid": exid, "position": pos, "intlength": intlength,
                "decimals": 0, "paramtext": p.text,
            })
        # basXML off: the client then sends classic TLV requests (0x0201 name / 0x0203 value), which
        # extract_inputs reads; with "X" NCo sends binary-XML requests instead.
        out[fn.name] = {"remote_call": "R", "update_task": "", "remote_basxml_supported": " ",
                        "params": params}
    return out


def ddic_entries(catalog):
    """Structures in the shape of load_ddic_catalog()."""
    out = {}
    for s in catalog.structures.values():
        fields = []
        for pos, f in enumerate(s.fields, 1):
            leng = f.type.chars if f.type.chars is not None else 10
            fields.append({
                "tabname": s.name, "fieldname": f.name, "position": pos, "keyflag": "",
                "datatype": f.type.abap, "leng": leng, "outputlen": leng, "decimals": 0,
                "inttype": _INTTYPE[f.type.abap], "intlen": f.type.byte_length,
                "offset": f.offset, "offset_uni": f.offset, "rollname": "", "reptext": f.text,
            })
        out[s.name] = fields
    return out


def tabname_index(rfm_catalog):
    """tabname -> largest INTLENGTH, as built in SAPGatewayService.setup_server."""
    index = {}
    for fm_info in rfm_catalog.values():
        for p in fm_info.get("params", []):
            tn = (p.get("tabname") or "").strip()
            il = p.get("intlength", 0) or 0
            if tn and il > 0:
                index[tn] = max(index.get(tn, 0), il)
    return index


def extract_inputs(raw, fn):
    """Values of the character-like import/changing parameters found in the request.

    A parameter is sent as a name TLV (marker 0x0201, UTF-16LE name) followed by a value TLV (0x0203).
    """
    from pysap.SAPNWRFC import decode_value, find_tlv_field_by_marker

    raw = bytes(raw)
    inputs = {}
    for p in fn.parameters:
        if p.kind not in ("import", "changing") or p.scalar is None:
            continue
        if p.scalar.abap not in _CHAR_LIKE:
            logger.error("bapi_fixtures: %s.%s is %s; only character-like inputs can be matched",
                         fn.name, p.name, p.scalar.abap)
            continue
        name = _u16(p.name)
        start = 0
        while True:
            idx = raw.find(name, start)
            if idx < 0:
                break
            # Exact name TLV: [prev:2][0x0201][len:2][name]
            if idx >= 4 and raw[idx - 4:idx - 2] == b"\x02\x01" and \
                    struct.unpack("!H", raw[idx - 2:idx])[0] == len(name):
                val, _ = find_tlv_field_by_marker(raw, b"\x02\x03", idx + len(name))
                if val is not None:
                    inputs[p.name] = decode_value(val) or ""
                break
            start = idx + 1
    return inputs


def _text(value, chars):
    return _u16(str(value)[:chars].ljust(chars))


def _row(structure, values):
    buf = bytearray(structure.byte_length)
    for f in structure.fields:
        data = _text(values.get(f.name, ""), f.type.chars)
        buf[f.offset:f.offset + len(data)] = data
    return bytes(buf)


def answer_tlvs(catalog, fn, answer, prev=0x0512):
    """TLVs for the outputs in *answer*: scalars (name + value), then tables (name, index, size, rows).

    Returns (body, last_marker, problems).
    """
    body = b""
    problems = []
    for p in fn.parameters:
        if p.kind not in ("export", "changing") or p.name not in answer:
            continue
        if p.scalar is None or p.scalar.abap not in _CHAR_LIKE:
            problems.append("%s.%s: only character-like exports are sent" % (fn.name, p.name))
            continue
        body += _tlv(prev, 0x0201, _u16(p.name))
        body += _tlv(0x0201, 0x0203, _text(answer[p.name], p.scalar.chars))
        prev = 0x0203
    tables = [p for p in fn.parameters if p.kind == "tables"]
    for index, p in enumerate(tables, 1):
        if p.name not in answer:
            continue
        s = catalog.structures[p.structure]
        if any(f.type.abap not in _CHAR_LIKE for f in s.fields):
            problems.append("%s.%s: only tables of character-like fields are sent" % (fn.name, p.name))
            continue
        rows = [_row(s, r) for r in answer[p.name]]
        body += _tlv(prev, 0x0301, _u16(p.name))
        body += _tlv(0x0301, 0x0330, struct.pack("!I", index))
        body += _tlv(0x0330, 0x0302, struct.pack("!II", s.byte_length, len(rows)))
        prev = 0x0302
        for r in rows:
            body += _tlv(prev, 0x0303, r)
            prev = 0x0303
    return body, prev, problems


class BapiFixtureSource(object):
    """Reloading view of a data folder, merged over the CSV catalogs of the server."""

    def __init__(self, root):
        from cpmf_bapi_fixtures import ReloadingCatalog  # optional dependency, only when configured
        self.root = root
        self._live = ReloadingCatalog(root)
        self._applied = None

    def refresh(self, server):
        """Return the current catalog (None if the folder never loaded); re-merge it when it changed."""
        from cpmf_bapi_fixtures import LoadError
        try:
            catalog = self._live.get()
        except LoadError as exc:
            logger.error("bapi_fixtures %s cannot be loaded:\n%s", self.root, exc)
            return None
        if catalog is not self._applied:
            rfm = dict(server.base_rfm_catalog)
            rfm.update(rfm_entries(catalog))
            ddic = dict(server.base_ddic_catalog)
            ddic.update(ddic_entries(catalog))
            server.rfm_catalog = rfm
            server.ddic_catalog = ddic
            server.tabname_intlength = tabname_index(rfm)
            self._applied = catalog
            logger.warning("bapi_fixtures %s: serving %d function(s), %d structure(s)",
                           self.root, len(catalog.functions), len(catalog.structures))
        return catalog
