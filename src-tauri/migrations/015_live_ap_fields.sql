-- LOCKON EWAC: persist the three access-point fields that only ever existed live
-- Version: 15
--
-- `radio_type`, `connected_stations` and `channel_utilization_pct` come from the
-- Windows `netsh wlan` parser (`engine/scanner/netsh_wlan.py`), are declared on
-- the `AccessPoint` type, and are rendered in the live scan feed. They were
-- absent from the `access_points` INSERT, so they existed for the lifetime of
-- the scan and nowhere else.
--
-- The consequence the README already stated as a known gap: "this open AP had
-- twelve clients on it" is visible during the drive and gone afterwards. It is
-- also one of the more useful facts a report can carry — an open network with
-- no clients is a different finding from an open network carrying a dozen
-- devices, and only the second one has anybody's traffic on it.
--
-- All three are nullable with no default, which is the honest representation:
-- most adapters and most scans do not report them, and a zero would say
-- "measured, none" for a field that was never measured. `connected_stations`
-- in particular must never default to 0 — that is the difference between "no
-- devices were on this network" and "the adapter does not report BSS Load".

-- 802.11 generation string as the OS reports it, e.g. "802.11ac", "802.11ax".
ALTER TABLE access_points ADD COLUMN radio_type TEXT;

-- Stations associated with this AP, from the BSS Load information element.
-- NULL means the field was absent, which is the common case.
ALTER TABLE access_points ADD COLUMN connected_stations INTEGER;

-- Channel utilisation as a percentage, also from BSS Load. NULL when absent.
ALTER TABLE access_points ADD COLUMN channel_utilization_pct REAL;
