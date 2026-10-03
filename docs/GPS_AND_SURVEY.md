# GPS and survey technique

> **[← Back to the README](../README.md)** ·
> [Install](INSTALL.md) · [Architecture](ARCHITECTURE.md) · [Testing](TESTING.md) · [Troubleshooting](TROUBLESHOOTING.md) ·
> [Engineering log](ENGINEERING_LOG.md) · [Playbook](PLAYBOOK.md) · [AP location methods](AP_LOCATION_METHODS.md)

This is the one part of the tool where **what you do decides whether the output
is usable**, and no setting can compensate for getting it wrong. Everything else
in these documents describes what the software does; this describes what it
needs from you.

The short version: **buy a puck and put it on the roof, and turn a corner.**

---

## Why this matters more than any setting

An access point's position is fixed by where range estimates taken **from
different places** intersect. From one place they do not intersect — they merely
agree, which is not the same thing and cannot be solved.

That means two failures are entirely yours to prevent:

* **No usable fix** → access points are recorded with no coordinates at all.
  They exist in the scan, and they cannot be mapped, ever, afterwards.
* **No movement** → coordinates exist, but no estimator can run. The tool
  reports the positions as unresolved rather than inventing them.

Neither is recoverable after the drive. Both are cheap to avoid.

---

## The receiver

A hardware GPS module that outputs **NMEA 0183** over a USB serial (COM) port.
There is no software fallback and no network-location mode.

**Recommended modules**

| Module | Why |
|---|---|
| **GlobalSat BU-353-S4** | USB puck, weatherproof, magnetic mount. Built for exactly this and the easiest way to get the antenna onto the roof |
| **u-blox NEO-6M / NEO-M8N** | Cheap, reliable, very well supported. Usually a bare board — you supply the mounting |

Set the COM port and baud in **Settings**; the default is `9600`, which is what
most NMEA modules ship with.

### Antenna placement beats module choice

HDOP — the satellite geometry figure — is set almost entirely by how much sky
the antenna can see, and HDOP is what the engine gates on.

| Placement | Typical HDOP | Result |
|---|---|---|
| Roof, magnetic puck | 1 – 2 | Everything works |
| On the windscreen | 1 – 3 | Fine |
| Dashboard under a raked screen | 3 – 8 | Intermittent; readings start being dropped |
| In a bag, on a seat, in a glovebox | > 5 | **Every reading rejected. No positions recorded at all** |

A magnetic puck on the roof is the single cheapest improvement available to a
survey, and it outranks spending more on the module.

### Refresh rate

1 Hz is adequate for urban surveying: at 40 km/h you cover about 11 m per
second, comfortably above the 5 m movement threshold. A 5 Hz or 10 Hz module
helps at highway speed, where 1 Hz leaves roughly 25 m between consecutive
points.

### Wait for the fix before scanning

A cold start takes 30–60 seconds, and longer from a cold boot in an unfamiliar
city. Access points seen before the first valid fix carry no position. The
status readout shows the live satellite count and HDOP — start when it is
reporting a fix, not when the app has finished loading.

---

## What the engine does with your readings

Four gates, in order. Each exists because it was once missing and something
wrong was drawn on the map — see
[the pipeline diagram](ARCHITECTURE.md#gps-quality-pipeline).

| Gate | Threshold | What a failure looks like to you |
|---|---|---|
| **Fix validity** | GGA `gps_qual` > 0, RMC `status` = `A` | No position recorded. A receiver with no lock still emits sentences carrying a stale latitude, and those are refused rather than plotted |
| **Satellite geometry** | HDOP ≤ 5.0 | Access points recorded with **no coordinates**. They are in the scan and cannot be mapped |
| **Plausibility** | Implied speed ≤ 200 km/h between fixes | A multipath jump is dropped rather than drawn as travel |
| **Movement** | ≥ `GPS_STEP_M` (5 m) since the last recorded point | Nothing is added to the track while you are stationary |

A receiver that cannot hold HDOP ≤ 5 does not give you *worse* positions. It
gives you **none**, quietly, and you discover it when the report says the access
points could not be placed.

---

## How to drive so positions can be resolved

### 1. Move at least 25 m past each access point

Below `MIN_ALONG_TRACK_M` no estimator runs at all. `estimateLocation` refuses
before dispatching to any method and reports the position as unresolved, marking
where you stood instead of inventing a transmitter location — because solving
for a transmitter a hundred metres away from a cluster of sightings ten metres
across is ill-conditioned, and a few dB of fading moves the answer by tens of
metres.

A survey taken from a parked vehicle locates nothing. The map groups those into
one counted marker per place you stopped rather than pretending otherwise.

### 2. Turn a corner — do not drive the same street twice

With every sighting on one straight line the likelihood is symmetric about that
line, so **which side the transmitter is on cannot be determined**. Measured over
five noise seeds per route, transmitter 40 m off the road:

| route | median error | wrong side |
|---|---|---|
| single straight pass | 31 m | 2 of 5 |
| **same street driven twice** | 25 m | **5 of 5** |
| two parallel streets | 13 m | 0 of 5 |
| **route with one turn** | **5 m** | **0 of 5** |
| loop around the block | 14 m | 0 of 5 |

**A second pass down the same street is the one thing that reliably makes it
worse** — it reinforces the symmetry rather than breaking it. One turn takes the
median error from 31 m to 5 m and removes the ambiguity entirely.

If you can only do one thing differently, do this one.

### 3. Keep moving, at a steady moderate speed

The scan interval is 1.5 s, about 16 m at 40 km/h — dense enough to catch an
access point from several positions. Much faster and each radio gets a handful
of sightings spread too thinly. Stopped, you get many sightings from one place,
which is the case that cannot be solved at all.

### 4. Watch HDOP, not the satellite count

Twelve satellites in a bad arrangement are worse than six in a good one.
Readings above HDOP 5.0 are rejected outright, so a poor sky view does not
degrade your positions — it removes them.

---

## What the report tells you afterwards

The position quality section states the recorded track's extent in metres, how
many positions were mirror-ambiguous, and how many could not be resolved at all.
The survey map draws unresolved positions hollow and groups them.

If it says the receiver never moved far enough, that is a statement about the
drive and not about the tool. The fix is to go back and drive past them.

For the mathematics behind all of this — why a straight route is ambiguous, what
the error radius means, and what each estimator can and cannot do — see
[AP location methods](AP_LOCATION_METHODS.md).
