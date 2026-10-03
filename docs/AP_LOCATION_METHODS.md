# The Encyclopedia of Access Point Geolocation

> **[← Back to the README](../README.md)** ·
> [Install](INSTALL.md) · [Architecture](ARCHITECTURE.md) · [Testing](TESTING.md) · [Troubleshooting](TROUBLESHOOTING.md) ·
> [Engineering log](ENGINEERING_LOG.md) · [Playbook](PLAYBOOK.md) · [AP location methods](AP_LOCATION_METHODS.md) · [GPS & survey](GPS_AND_SURVEY.md)


Wardriving and passive Signal Intelligence (SIGINT) inherently suffer from one major physical limitation: **You never know exactly where the Access Point (AP) is.** You only know where *you* were, and how strong the signal was at that exact moment.

Estimating the physical location of an AP from a moving vehicle is a complex mathematical problem involving Free Space Path Loss (FSPL), urban signal reflection, and GPS inaccuracy.

This document serves as an encyclopedia of the various geolocation algorithms developed and tested during the creation of **LOCKON EWAC**, detailing their mathematical theories, strengths, and weaknesses.

---

## 1. The "Highest RSSI" Method (The Naive Approach)
**Status:** Active as the fallback only — used when there are too few sightings for anything better, and the estimate says so

The simplest method used by many early wardriving tools (like older versions of WiGLE/Kismet clients). 
It simply records every signal ping, and whatever GPS coordinate had the strongest RSSI (e.g., `-45 dBm`), it assumes the AP is standing exactly at that GPS coordinate.

### How it works:
```python
if current_rssi > highest_recorded_rssi:
    ap_location = current_gps_location
```

### The Flaw:
- **The "Drive-By" Error:** APs are almost never in the middle of the street. If you drive past a house, the strongest signal is on the road directly in front of the house. This method will ALWAYS place the AP in the middle of the road, never inside the building where it actually belongs.
- **It used to understate its own error threefold.** LOCKON keeps this method as the fallback when there are too few sightings for anything better, and it reported the modelled distance to the AP *as* its error radius: 14 m of claimed uncertainty against 42 m of measured error, printed in the report as if it were a confidence bound. A distance derived from one reading carries the shadowing spread of that reading, so the radius is now multiplied by `SINGLE_READING_DISTANCE_FACTOR_95 = 10^(2*sigma / (10*n))` — about 3.0x at 6 dB and an exponent of 2.5. Derived from the model rather than written down, so it follows if either changes. Measured agreement after the fix: 42/44, 64/69 and 39/36 m.

---

## 2. Weighted Centroid (Center of Mass)
**Status:** Active, offered as "Track Position" — a sanity baseline, not the default

Instead of picking a single point, this method averages all the GPS coordinates where the AP was seen, pulling the "center" closer to the points with the strongest signals.

### How it works:
It uses a weighted average of Latitude and Longitude:

$$ Lat_{center} = \frac{\sum (Lat_i \times W_i)}{\sum W_i} $$
$$ Lon_{center} = \frac{\sum (Lon_i \times W_i)}{\sum W_i} $$

The weight is **inverse modelled distance** — `W = 1 / max(1, rssiToDistanceM(rssi, frequency))`
(`estimateTrackPosition` in `src/lib/localization.ts`).

> **This section previously gave the weight as $W = 10^{RSSI/10}$**, which is
> what the code used to do and no longer does. That formula is still worth
> understanding, because it is the reason the method was renamed: see the second
> weakness below.

> **Renamed to "Track Position" in the app**, because calling it a localization
> method oversold it. See the measurement below.

### Strengths & Weaknesses:
- ✅ **Ultra-Fast:** Extremely lightweight (~0.02 ms per AP). Perfect for real-time MapGL rendering.
- ✅ **Stable:** Doesn't jump around erratically.
- ❌ **It cannot leave the path you drove. This is not a flaw to be tuned out — it is what the operation is.** A weighted average is a *convex combination* of the sighting positions, so the result is always inside their hull. If every sighting is on one road, the answer is on that road. Measured off-track displacement with the AP 40 m from the road: **0.0 m in every trial**.
- ❌ **The original weighting made it worse.** `W = 10^(RSSI/10)` puts a 10,000:1 ratio between a −40 and a −80 dBm reading, so the single strongest sample swamped everything and the result was peak RSSI under another name. The app now weights by inverse modelled distance, which keeps the other samples in play.
- 🚧 **None of this runs without a baseline.** Below `MIN_ALONG_TRACK_M` the gate in `estimateLocation` returns an unresolved position before any estimator is reached — see §4d. This is not a limitation of this method; it applies to all three equally, because no search can recover a position the geometry does not contain.
- 🎯 **Use it as** a fast sanity baseline, and read the Likelihood Grid when you need a position off the surveyed track.

---

## 3. Multilateration (least squares over modelled ranges)
**Status:** Active, offered as "Multilateration" — competitive once the route has real shape, no better than the naive baseline without it

The idea is the one behind GPS: if you know your distance from several known
points, the position consistent with all of them is the answer.

### How it works (`estimateTrilateration` in `src/lib/localization.ts`):
1. Convert each sighting's RSSI to a modelled range with the **same
   frequency-corrected log-distance model** the rest of the app uses — see §4:
   `rssiToDistanceM = 10^((ref − rssi) / (10·n))`, `PATH_LOSS_EXPONENT = 2.5`,
   reference −40 dBm at 1 m with a `20·log10(f/2437)` band correction.
2. Solve for the position by **Gauss–Newton with Levenberg–Marquardt damping,
   over every sighting, run to convergence** (up to 100 iterations) — not three
   circles intersected geometrically.
3. Derive the error radius from the **covariance of the least-squares solution**,
   `Cov = σ_r² (JᵀJ)⁻¹`, taking the larger principal standard deviation and
   scaling it by `RADIUS_95_SIGMA`.

> **This section previously described two things the code does not do:** an FSPL
> formula (`10^((27.55 − 20·log10(f) + |RSSI|)/20)`), which appears nowhere in
> the codebase, and taking "the 3 strongest observations" and intersecting
> circles. Using only the strongest readings is specifically the mistake §2
> documents — the distant weak readings are what tell the model how far away the
> transmitter is. The §4 description and `README.md` have always described the
> real model; this section had drifted.

### Strengths & Weaknesses:
- ✅ **Pushes off the road:** unlike Track Position, this can place the transmitter away from the surveyed path.
- ✅ **The radius now reflects the geometry, not the noise.** It used to be `median range residual × 1.5`, which measures how well the modelled ranges agree with each other — a property of the shadowing, not of how tightly the geometry pins the position. Measured, that radius was *anti-correlated* with the method's own accuracy: 4.1× the true error on a loop, and 1.0× on a straight pass where it covered the error in only 4 runs out of 10 while claiming to be a 95% bound. With the covariance form, collinear sightings make `JᵀJ` nearly singular across-track, so the ill-conditioning that causes the mirror ambiguity is what inflates the radius. That inflation is a *per-mode* spread and was not enough on its own — it covered the transmitter in 52% of runs on a straight pass — so the radius is also widened to reach the second candidate, and the per-mode figure is reported separately. See §4.
- ❌ **The "Urban Canyon" flaw:** RF bounces off buildings, trees and vehicles. A weak signal may mean an obstruction rather than distance, and the path-loss model cannot tell the difference. This is why the shadowing term exists and why the radius is wide in built-up areas.
- ❌ **Needs route shape.** On a straight pass the cross-track direction is unconstrained and the result is mirror-ambiguous; the app reports both candidates and the distance between them rather than picking one. A second candidate is only offered when it is more than `MIRROR_MIN_SEPARATION_M` (1 m) from the first: on a mathematically straight pass the reflection *is* the first point, and "two equally good positions, 0 m apart" was printed in the PDF, the CSV and the KML, with a duplicate placemark joined by a zero-length line.
- 🚧 **None of this runs without a baseline.** Below `MIN_ALONG_TRACK_M` the gate in `estimateLocation` returns an unresolved position before any estimator is reached — see §4d. This is not a limitation of this method; it applies to all three equally, because no search can recover a position the geometry does not contain.

---

## 4. Bayesian Probability Grid
**Status:** **Active — the default, and the method the app marks RECOMMENDED**

A statistical approach that divides the map into a grid and calculates, for each cell, how well a transmitter there would explain every observed signal. The search is coarse-to-fine rather than a single fixed resolution: it starts wide and refines around the winner to roughly 1.2 m.

### How it works (`src/lib/localization.ts`, `estimateBayesian`):
1. Take a search box around the observations.
2. For every candidate position in the grid, calculate the *expected* RSSI there from the frequency-corrected path-loss model.
3. Compare expected against observed and assign a Gaussian likelihood using `SHADOWING_SIGMA_DB`.
4. Sum the log-likelihoods across observations; the best cell is the estimate.
5. **Expand and repeat.** If the peak lands on the edge of the box the search widens and runs again, and the estimate records how many times it had to. Without that, a transmitter outside the initial box was silently pinned to the boundary.
6. Refine around the winner for sub-cell resolution, then derive the error radius from the shape of the likelihood surface.

### Strengths & Weaknesses:
- ✅ **Most accurate of the three** on every route measured (see the comparison below), and the only one that still produces a useful answer from a single straight pass.
- ✅ **Can place a transmitter off the surveyed path** — it searches positions, it does not average the ones you drove through.
- ✅ **Reports its own uncertainty:** an error radius in metres, plus a mirrored candidate when the route geometry cannot rule one out.
- ❌ **The most expensive of the three.** Cost is grid cells x sightings, so the sighting set is capped at `GRID_SEARCH_MAX_POINTS = 40` chosen by `selectDiverse` — which keeps the geometry and the full signal range rather than just the strongest readings. Live scanning is bounded by a per-second budget; archive post-processing runs uncapped and yields to the event loop.
- ⚠️ **Implemented in TypeScript, not NumPy.** The vectorised NumPy work in this project is the GPR surface in `engine/scanner/gpr_engine.py`; the live grid runs in the frontend.
- 🚧 **None of this runs without a baseline.** Below `MIN_ALONG_TRACK_M` the gate in `estimateLocation` returns an unresolved position before any estimator is reached — see §4d. This is not a limitation of this method; it applies to all three equally, because no search can recover a position the geometry does not contain.

---

## 4b. What the three selectable methods actually score

Measured, not estimated. A simulated transmitter 40 m off the road, 6 dB
log-normal shadowing, 40 noise seeds per route, median absolute error in
metres. Reproduce with the harness in `tests/localization.test.mjs`.

| Route driven | Likelihood Grid | Multilateration | Track Position | Peak RSSI |
|---|---|---|---|---|
| Straight, 300 m | **13 m** \* | 42 m \* | 40 m | 42 m |
| Same street twice | **12 m** \* | 43 m \* | 40 m | 43 m |
| Two parallel streets | 9 m \* | **8 m** | 7 m | 44 m |
| One turn (L-shape) | 11 m | **8 m** | 15 m | 42 m |
| Loop around the block | **14 m** | 15 m | 19 m | 50 m |

\* On a mirror-ambiguous route this is the error to the **nearer of the two
candidates the estimator offers**, not to the one it happens to report. The
distinction is not a technicality: the two candidates sit about 80 m apart, so
the error to the reported one is a coin flip whose median swings between roughly
20 m and roughly 80 m on noise alone and measures nothing about the estimator.
How often it reports the wrong one is a separate fact, and it is the one that
matters:

| Route driven | runs where two candidates were offered | wrong one reported |
|---|---|---|
| Straight, 300 m | 40/40 | **23/40** |
| Same street twice | 40/40 | **19/40** |
| Two parallel streets | 22/40 | 3/40 |
| One turn (L-shape) | 17/40 | 5/40 |
| Loop around the block | 13/40 | 2/40 |

A straight pass is a coin flip and the tool says so on every single run. That is
the honest outcome, not a defect — see §4c.

Reading it:

- **The grid wins or ties everywhere**, and is the only method that still works
  from a single straight pass. That is why it is the default.
- **Multilateration only beats it where the route has real shape.** It needs
  more sightings than the others and a geometry that constrains the ranges.
- **Track Position is a convex combination of the sighting positions**, so it
  cannot leave the path. On a straight pass its error is essentially the
  distance from the road to the transmitter — it is measuring the road, not the
  radio. Use it to sanity-check that the track itself looks right.
- A naive "wrong side of the road" count run against Track Position will look
  terrible on a straight route. That is an artifact: the estimate sits *on* the
  road, so a side test taken at the road's own latitude is a coin flip.

---

## 4b-ii. Is the stated radius worth anything?

An error radius is only useful if it discriminates a good fix from a poor one.
Measured over ten seeds per route — median ratio of stated radius to true error,
and how often the radius actually covered the error:

| route | Likelihood Grid | Multilateration |
|---|---|---|
| straight 300 m | 1.6x, **10/10** | 3.5x, **10/10** |
| same street twice | 2.4x, 10/10 | 3.9x, 10/10 |
| two parallel streets | 4.9x, 10/10 | 2.2x, 10/10 |
| one turn (L) | 6.8x, 10/10 | 2.2x, 10/10 |
| loop the block | 3.4x, 10/10 | 1.2x, **5/10** |

Multilateration's radius on a loop covers the error only half the time. It
derives its covariance from the least-squares normal matrix, which describes how
well the *ranges* pin the solution and knows nothing about the ranges all being
wrong together — which is exactly what an unknown transmit power does to them.
The grid's radius accounts for that (§4b-iii); multilateration's does not, and
it is not the default.

Two defects were found getting here, both of which put a misleading number in
the report:

**Multilateration reported the wrong quantity entirely.** Its radius was
`median range residual x 1.5` — how well the modelled ranges agree with each
other, which is a property of the shadowing on the RSSI readings and not of how
tightly the geometry constrains the position. The two do not merely differ, they
move in opposite directions: the measured radius was **4.1x** the true error on
a loop (a good fix with noisy ranges) and **1.0x** on a straight pass, where it
covered the error in only **4 runs out of 10** while claiming to be a 95% bound.
It is now the covariance of the least-squares solution,
`Cov = sigma_r^2 (J^T J)^-1`, where each row of `J` is the unit bearing from a
sighting to the solution. Collinear sightings make `J^T J` nearly singular along
the cross-track direction, so the ill-conditioning that *causes* the mirror
ambiguity also inflates the radius.

> **That inflation was not enough on its own, and this paragraph used to claim it
> was** — "the ill-conditioning that causes the mirror ambiguity is what inflates
> the radius, which is what a reader was entitled to assume it already did". A
> covariance is a *per-mode* spread: it describes how far the transmitter may be
> from the mode that was solved for, and says nothing about the other mode. On a
> realistic straight pass the solver picked the wrong side of the road in **48% of
> 200 runs**, and the per-mode radius contained the transmitter in **52%** of them
> while the report printed it under a heading saying 95%. A bound that holds half
> the time is not a bound, and this is the shape of wrong that reads as careful
> work: a plausible number, correctly computed, labelled as something it is not.
>
> The radius is now widened the way the likelihood grid has always widened its
> own — `max(radius, mirrorDistance + modeRadius)`, since the transmitter is
> within `modeRadius` of one of two modes `mirrorDistance` apart — and that covers
> it in 200 runs out of 200. The per-mode figure is published separately as
> `location_mode_error_m`, which is what the report's "Per-mode" column prints.
>
> Two things made this invisible for as long as it was. The widening and the
> separation were both computed only by the grid, so there was nothing to compare;
> and the test fixture for a straight pass put all sixty sightings at one exact
> latitude, which makes `J^T J` *exactly* singular — the solver takes no step, the
> answer stays on the track, reflecting a point across an axis it already lies on
> returns the point itself, and so multilateration produced no second candidate on
> that fixture at all. Every mirror assertion written against it passed without
> running. A metre and a half of lateral wobble, less than any real receiver's
> scatter, makes all forty seeds exercise the branch.

**Both estimators used 2 sigma for a "95%" bound.** For a circular bivariate
normal the radius follows the Rayleigh law, `P(r < k sigma) = 1 - exp(-k^2/2)`,
so 2 sigma covers **86.5%**, not 95%. `RADIUS_95_SIGMA = sqrt(-2 ln 0.05)` =
2.448 is now derived rather than written down, and both estimators use it.

**What is deliberately not "fixed":** the peak-RSSI fallback covers only about
5 runs in 10 when measured against sixty sightings. That measurement exercises a
path the app never takes — the fallback is reachable only when there are fewer
than three sightings, where the bias is negligible. The bias is real, though:
the *strongest* of N noisy readings is the luckiest one, so its implied distance
is short by roughly `sqrt(2 ln N)` sigma. Inflating the constant to satisfy a
benchmark of a path that does not run would make the real path wildly
over-conservative. If peak is ever promoted to a selectable method, that
correction has to come with it.

---

## 4b-iii. The transmitter's power is unknown, and that had to be paid for

Every measurement above simulates a transmitter whose power is exactly the
constant the estimator assumes: `REFERENCE_2G4_DBM = -40 dBm at 1 m`. That makes
them a test of the *search*, not of the *model*. Real equipment is nowhere near
that uniform — a ceiling-mounted enterprise access point at full EIRP against a
phone hotspot is well over 10 dB apart before antenna gain — and a passive
survey has no way to tell which one it is looking at.

The consequence is not a wider answer, it is a **moved** one. Every modelled
distance scales by `10^(D / 10n)` for a power error of `D` dB, so at `n = 2.5`
a 6 dB error scales every range by 1.74x, and the fit slides the transmitter
toward or away from the road to absorb it. Measured on the L-shaped route, 200
trials per row:

| real power vs assumed | median error | stated radius covered the truth |
|---|---|---|
| exactly as assumed | 9.3 m | 98% |
| 3 dB of spread | 13.5 m | 77% |
| **6 dB** | **18.1 m** | **52%** |
| 10 dB | 25.3 m | 43% |

The report prints that radius as "roughly 95% of the posterior". At the ordinary
case of a few dB it was covering the truth about half the time.

### The obvious fix is worse, and that is why it did not ship

The textbook answer is to profile the power out. For any candidate position the
best-fit power is just the mean of `rssi + 10n·log10(d)`, so it can be
eliminated analytically — subtract that mean and the objective becomes the
*variance* of the residuals, which is invariant to transmit power by
construction. What remains identifiable is the **shape** of the signal along the
route, which is the part that genuinely carries the perpendicular distance: a
transmitter close to the road makes a sharp peak, a distant one a broad rise.

Measured, it is a clear loss. With the power exactly as assumed, the L-shaped
route went from 9.3 m to 22.2 m, coverage from 98% to 53%, and the 90th
percentile error to 202 m. Removing the absolute level flattens the likelihood
surface enough that the estimate runs away; 6 dB of shadowing over a few dozen
sightings does not leave enough shape to replace it.

> A caution from doing this measurement. The free-fit column initially read
> 40.3 m on a straight pass and looked like the best option in the table. It was
> not an estimator at all: `shrink = n·tau² / (n·tau² + sigma²)` is `Inf/Inf`
> when written literally, every `ll > best` comparison against NaN is false, and
> the grid search therefore kept its starting point and returned the centre of
> the route — which on that route is 40 m from the transmitter because that is
> the perpendicular offset. A plausible coordinate produced by a search that
> never ran. `tests/localization.test.mjs` now pins the limit explicitly.

### What shipped: a prior, chosen by sweep

The power is allowed to move, but not freely. Minimising
`sum((e_i - D)²)/sigma² + D²/tau²` over the offset `D` gives
`D* = mean(e) · n·tau² / (n·tau² + sigma²)`, so `tau` interpolates between
pinning the power (`tau = 0`, the original behaviour) and fitting it outright.
Median error on the L-shaped route, 200 trials per cell:

| prior `tau` | 0 dB | 1 dB | **2 dB** | 3 dB | 6 dB | free |
|---|---|---|---|---|---|---|
| power known | 9.3 | 9.6 | **11.4** | 13.0 | 15.0 | 22.2 |
| sigma 3 dB | 13.5 | 12.0 | **11.7** | 13.1 | 16.1 | — |
| sigma 6 dB | 18.1 | 15.7 | **13.9** | 13.7 | 16.0 | 20.8 |
| sigma 10 dB | 25.3 | 20.6 | **16.8** | 16.2 | 15.9 | 23.6 |

`POWER_PRIOR_DB = 2` costs about two metres when the assumption happens to hold
— which it never exactly does — and returns four to eight once it does not.

Separately, the **stated radius** is widened by the positional error that
`TX_POWER_SPREAD_DB = 6` dB of unmodelled power difference would induce. That
error is proportional to the estimate's distance from the nearest sighting,
because a power error scales every modelled range by the same factor: beside the
road it is negligible, a hundred metres off it dominates. A flat margin would be
wrong in both directions. It is added in quadrature with the posterior width.

| real power vs assumed | median before | median after | coverage before | coverage after |
|---|---|---|---|---|
| exactly as assumed | 9.3 m | 11.4 m | 98% | **100%** |
| 3 dB | 13.5 m | **11.7 m** | 77% | **96%** |
| 6 dB | 18.1 m | **13.9 m** | 52% | **94%** |
| 10 dB | 25.3 m | **16.8 m** | 43% | **89%** |

Both constants are published in the report's method appendix through
`describeLocalizationMethodology()`, so a reader can see what was assumed about
a transmitter nobody measured.

## 4c. Survey geometry: shape, and also scale

Two different things stop a position being trustworthy, and they need opposite
fixes from the operator.

**Shape.** With every sighting on one straight line the likelihood surface is
symmetric about that line: a transmitter 40 m left and one 40 m right explain
the measurements equally well, and no algorithm can choose between them.
Driving the same street again makes it *worse*, because a second pass only
reinforces the symmetry. One turn resolves it. Detected as
`crossTrack / alongTrack < LINEARITY_AMBIGUOUS_BELOW` (0.15), and the estimate
then carries a mirrored candidate and a widened radius rather than presenting a
coin flip as a fact.

**Scale.** Consumer GPS scatter is roughly circular, which scores a
near-perfect linearity ratio. The ratio measures the shape of the cloud and
never asked how big it was, so a parked rig was told *"2 m of deviation across
5 m of travel. Enough shape to determine which side of the track an AP lies
on."* Five metres of jitter is no baseline at all. Now gated on absolute
distance as well:

| Constant | Value | What it rejects |
|---|---|---|
| `MIN_ALONG_TRACK_M` | 25 m | Sightings that never travelled — a stationary receiver's scatter |
| `MIN_CROSS_TRACK_M` | 8 m | Perpendicular deviation within GPS noise, however good the ratio looks |
| `LINEARITY_AMBIGUOUS_BELOW` | 0.15 | A route that is straight relative to its own length |
| `POWER_PRIOR_DB` | 2 dB | The assumption that every transmitter runs at the reference power (§4b-iii) |
| `TX_POWER_SPREAD_DB` | 6 dB | A radius that describes only the fit, and not the assumption the fit rests on |

The two conditions are deliberately **not** merged. `insufficientBaseline` is
the along-track test alone: a dead-straight 165 m drive has zero cross-track
spread and plenty of baseline. It is mirror-ambiguous, not stationary, and
telling that operator to "drive past the access point" when they just did would
be worse than saying nothing. The Settings panel therefore has three states —
**STATIONARY**, **STILL A LINE**, and **SHAPED** — and names which one applies.

---

## 4d. When the answer is that there is no answer

For a long time `insufficientBaseline` was *detected* and then ignored. It set
the mirror-ambiguous flag, wrote a note and tinted a label in Settings — and the
estimator ran anyway, and its answer was published like any other.

That is worse than it sounds, because the answer is not merely imprecise, it is
**unstable**. Solving for a transmitter a hundred metres away from a cluster of
sightings ten metres across is ill-conditioned: a few dB of fading moves the
solution by tens of metres, so every re-estimate puts the access point somewhere
new. Reported from the field as *"the access points never settle"*, and it is
also why choosing Multilateration appeared to scatter the points rather than
tighten them — the most geometry-hungry method is the one that degrades worst
when there is no geometry.

**`estimateLocation` now gates before dispatch.** Not inside each estimator:
this is not a property of the method chosen. No estimator can recover a position
the geometry does not contain, and three of them failing in three different ways
produced three wrong answers instead of one honest refusal.

Below `MIN_ALONG_TRACK_M`, `estimateUnresolved` reports:

| Field | Value | Why |
|---|---|---|
| position | the **mean** of where the receiver stood | A mean, not the strongest sighting: it does not hop between scatter points as the signal flickers, and a position that twitches is read as information when it is noise |
| `resolved` | `false` | Carried into the archive and the report, so a figure cannot redraw it as an ordinary coordinate |
| `errorRadiusM` | the distance the strongest reading implies, corrected and widened | See below |
| notes | how far the receiver travelled against what was needed, and that moving resolves it | A refusal has to say what would fix it |

The claim being made is then exactly one the data supports: *the transmitter is
somewhere within this circle of where you were standing.*

### The radius needed two corrections, in opposite directions

**It was three times too small.** `estimatePeak` carries a warning that the
strongest of *n* readings is the luckiest one — high by about
`sigma * sqrt(2 ln n)`, so the distance it implies is short by the same factor —
and that *"if this is ever promoted to a selectable method, that correction has
to come with it."* Running over a forty-sighting parked survey is exactly that
case. Measured without the correction, the stated radius covered the true
position in **4 runs in 10**. `peakDistanceCorrection` removes the bias.

**Then it was four times too large.** The first correction applied
`SINGLE_READING_DISTANCE_FACTOR_95` on top, which double-counts: once the bias
is removed, what remains is the uncertainty of the *maximum* of n samples, and
that is tighter than one sample by roughly `sqrt(2 ln n)`. The result covered
100% of the time at a median radius **4.2x** the error it was covering — a
circle 1.4 km across for a transmitter 279 m away. True, and not a finding
anyone can act on. `peakSpreadFactor95` uses the max-of-n spread: measured over
400 parked surveys, **99.5% coverage at 2.3x**, against a field documented as
"roughly 95%".

Both sides are asserted in `tests/localization.test.mjs`, because they pull
against each other and any radius covers if it is made large enough.

### What this looks like on the map

Every unresolved estimate lands on the receiver, so they collapse together —
measured at **1.6 m apart** across twelve transmitters 30 to 300 m away. Drawing
them individually stacks them into one unreadable pile that still implies twelve
distinct positions; dropping them leaves an empty map, which reads as "nothing
was there".

The tactical map groups them instead: **one marker per place the operator
stood**, carrying the number of access points heard from it. Grouped on a ~30 m
grid rather than averaged to a centroid, because an operator who stops twice has
two stationary clusters and a single averaged marker would sit between them,
where nothing was ever measured.

---

## 5. Gaussian Process Regression (GPR) / Machine Learning
**Status:** **Active (Offline Post-Processing)**

GPR fits a smooth surface through the RSSI values that were **measured** and returns the highest point of that surface.

> **What it is and is not.** This is a signal-field smoother, not a transmitter localizer. Every measurement comes from wherever the operator drove, so the fitted surface only exists over the driven path, and its maximum can only ever sit on or near that path. If the access point is 40 m off the road, the answer will be on the road. Use the Likelihood Grid when you need a position away from the surveyed track.

### How it works (`gpr_engine.py`):
1. Takes the GPS logs and RSSI values as training data: `X = [east, north]` in metres on a local tangent plane, `y = RSSI`.
2. Uses `scikit-learn` with an RBF kernel plus a WhiteKernel for multipath noise, and `normalize_y=True` so the prior mean is the mean measured RSSI.
3. Predicts over a grid spanning **only the measured extent** — no padding into space that was never surveyed.
4. Returns the peak of that surface, with an error radius in metres.

### Measured behaviour

Tested against simulated ground truth (AP 40 m off a 300 m road, 6 dB shadowing) in `engine/tests/test_gpr.py`:

| | error | reported confidence |
|---|---|---|
| **before** | **225 m**, outside the surveyed area | 69% |
| after | 40–44 m | 43% |
| peak RSSI baseline | 40–84 m | — |

Two defects caused the 225 m result, both now fixed:
1. `normalize_y` was left at scikit-learn's default of `False`, making the prior mean **0 dBm** — stronger than any real reading (measurements run −95..−65 dBm). Predictions away from data reverted toward it.
2. The prediction grid was padded 55 m beyond the data on every side, so the `argmax` escaped into that padding where the prior dominated.

### Strengths & Weaknesses:
- ✅ **Good smoother.** Where noise makes the raw peak jump, the smoothed field is steadier — in the 120-sample test it halved the error of raw peak RSSI (84 m → 40 m).
- ❌ **Cannot leave the driven path.** By construction. This is the important limitation.
- ❌ **Overhead.** Seconds per AP; archive-time only.
- 🎯 **Use Case in LOCKON:** a de-noised "where was the signal strongest" for archived missions, reported with its error radius so a reader can weigh it.

---

## 6. Advanced Theoretical & Hardware-Assisted Methods (External Concepts)
While LOCKON EWAC pushes the boundary of localized Wardriving using standard Wi-Fi adapters, the broader Signal Intelligence (SIGINT) and enterprise Wi-Fi fields utilize even more advanced methods requiring specialized hardware or controlled environments.

### A. Angle of Arrival (AoA) / Pseudo-Doppler Direction Finding
Instead of guessing distance based on signal strength (which is highly unreliable due to walls), this method determines the actual **Angle** the signal is coming from.
- **Hardware Requirement:** Requires an array of multiple antennas (Phased Array) or a rotating directional antenna (Yagi).
- **How it works:** By measuring the micro-second phase differences of the radio wave hitting different antennas in the array, the system can draw a straight line toward the target. Taking two readings from different GPS locations allows for perfect "Cross-Bearing Triangulation."
- **Use Case:** Fox-hunting, drone-based rogue AP hunting, and military SIGINT.

### B. Time of Flight (ToF) / 802.11mc Fine Timing Measurement (FTM)
RSSI is a terrible metric for distance. Modern Wi-Fi standards (IEEE 802.11mc) introduced FTM to fix this.
- **How it works:** The scanner and the AP exchange precisely timestamped packets. By measuring the Round Trip Time (RTT) of the packet at the nanosecond level, the exact distance is calculated using the speed of light ($c$).
- **Accuracy:** Often within 1 to 2 meters, completely immune to the "Urban Canyon" attenuation problems that plague FSPL.
- **Limitation:** The target AP *must* explicitly support and enable 802.11mc FTM protocols, making it useless for non-consensual hostile recon (Wardriving against legacy/unsupported routers).

### C. Dynamic Path Loss Exponent (PLE) Estimation
In our standard FSPL model, we assume a constant Path Loss Exponent (usually $n = 2.0$ for free space, or $n = 2.7$ for urban). 
- **The Concept:** Instead of using a hardcoded environment variable, a mathematical model dynamically estimates the specific PLE of the current street by analyzing how fast the signal decays as the vehicle drives away. 
- **Why it matters:** Driving past a wooden house has a different signal decay curve than driving past a concrete bank. Dynamically adjusting the PLE per-AP would theoretically improve Trilateration accuracy significantly.

### D. RF Fingerprinting / K-Nearest Neighbors (KNN)
Used almost exclusively for **Indoor Positioning Systems (IPS)** where GPS doesn't work.
- **How it works:** A surveyor walks through a building, recording the unique "Fingerprint" (the exact combination of signal strengths from all visible APs) at every 2-meter grid point, building an offline database.
- **Execution:** When a device wants to know its location, it takes a live reading, compares it against the database using a K-Nearest Neighbors (KNN) machine learning algorithm, and finds the closest matching fingerprint.
- **Limitation:** Highly brittle. Moving a couch or opening a door can change the RF fingerprint enough to break the tracking.

### E. Kalman & Particle Filters (Sequential Monte Carlo)
Used heavily in robotics, self-driving cars, and drone navigation. 
- **Kalman Filtering:** Attempts to track the AP as if it were a moving target, constantly updating a "belief" state with every new GPS ping. Best for tracking **moving APs** (like a mobile hotspot in another car).
- **Particle Filters:** Drops thousands of virtual "particles" (guesses) onto the map. As the wardriver moves and collects RSSI data, the algorithm "kills off" the particles that mathematically contradict the new readings. The surviving particles swarm around the true AP location. Highly effective for non-linear, unpredictable urban environments.

### F. 3D Ray-Tracing (RF Propagation Simulation)
The absolute pinnacle of RF geolocation, used by the military and telecommunication giants (for 5G tower placement).
- **The Concept:** Uses real-world 3D architectural data (like OpenStreetMap 3D building geometry).
- **How it works:** Instead of a simple math formula, the system uses a physics engine (similar to lighting Ray-Tracing in modern video games) to simulate exactly how radio waves bounce, refract, and penetrate through concrete, glass, and wood based on the city's 3D layout. 
- **Execution:** It runs thousands of simulations to find the only possible building layout that matches the bizarre echo patterns of the RSSI readings. Requires immense GPU compute power.

### G. Multi-Agent Synchronization
Used by crowd-sourced databases like WiGLE. 
- **How it works:** Instead of relying on a single drive-by, it takes data from thousands of different users driving down different streets over months.
- **Advantage:** Law of large numbers. Averages out the hardware differences of thousands of different smartphone antennas, effectively neutralizing the "Corner Flaw" of the Centroid method. LOCKON is designed for *solo tactical deployment*, so we rely on math rather than crowdsourcing.

### H. Time Difference of Arrival (TDOA)
The gold standard for wide-area military SIGINT and cellular (LTE/5G) tracking.
- **How it works:** Instead of a single wardriver, you deploy 3 or more static listening posts around a city. When a target AP transmits a packet, all listening posts record the exact microsecond they heard it.
- **Execution:** Because radio waves travel at the speed of light, the slight difference in arrival times (Time Difference) between the posts allows a central server to draw hyperbolic curves. Where the curves intersect is the AP.
- **Hardware Requirement:** Requires extreme hardware clock synchronization across all listening posts, typically achieved using GPS PPS (Pulse Per Second) signals.

### I. Channel State Information (CSI) / Wi-Fi Sensing
The bleeding-edge of Wi-Fi research. RSSI is just a single, crude number summarizing signal strength. CSI looks at the entire waveform.
- **The Concept:** Modern Wi-Fi uses OFDM (Orthogonal Frequency-Division Multiplexing), splitting the signal across 50+ subcarriers. CSI records the amplitude and phase shift of *every single subcarrier*.
- **Use Case:** By analyzing how specific subcarriers are distorted, systems can "see through walls," detect human breathing, recognize hand gestures, or map the exact shape of a room using nothing but standard Wi-Fi signals bouncing around.

### J. Wi-Fi SLAM (Simultaneous Localization and Mapping)
SLAM is traditionally used by robots and self-driving cars with Lidar or Cameras to map unknown environments. Wi-Fi SLAM does this using only radio waves and human footsteps.
- **How it works:** A person walks through an unmapped building holding a smartphone. The phone's IMU (Accelerometer & Gyroscope) counts their footsteps and turns (Dead Reckoning), while simultaneously recording Wi-Fi RSSI/CSI signatures.
- **Execution:** The algorithm mathematically "solves the maze," correcting the drift of the pedometer by recognizing when the user walks past the same Wi-Fi signal signature again (Loop Closure). It builds a complete indoor radio-map without GPS.

### K. Ultra-Wideband (UWB) Precision Ranging
While not strictly Wi-Fi, UWB is the ultimate successor to local RF positioning (used in Apple AirTags and military radars).
- **The Concept:** Instead of broadcasting a continuous wave of data like Wi-Fi or Bluetooth, UWB fires extremely short, high-bandwidth "pulses" (billions of pulses per second) across a massive spectrum.
- **Accuracy:** Because the pulses are so short, the Time-of-Flight (ToF) can be calculated with devastating precision, granting **centimeter-level accuracy** and total immunity to multi-path reflection (echoes) that ruin Wi-Fi FSPL.

### L. Frequency Difference of Arrival (FDOA) / Doppler Shift
Used in conjunction with TDOA.
- **How it works:** As a wardriving vehicle (or aircraft) moves toward a target AP, the radio waves are slightly compressed (higher frequency). As it drives away, they stretch out (lower frequency) — this is the Doppler Effect.
- **Execution:** By measuring these microscopic shifts in frequency across multiple observation points, highly advanced receivers can calculate the relative velocity and precise location of the transmitter without ever relying on signal strength.

---

## 7. The Final Frontier (Space & Airborne SIGINT)
When ground-based Wardriving is insufficient due to hostile terrain or physical barriers, the intelligence community escalates to the Z-axis.

### Drone Swarm Localization (3D Spatial Triangulation)
- **The Concept:** Deploying a swarm of autonomous UAVs (drones) equipped with Wi-Fi interceptors to fly in formation over a target area.
- **Execution:** Because the drones are in the air, they completely bypass the "Urban Canyon" effect (reflections from buildings/cars). By sharing RSSI and AoA data with each other in real-time, the swarm can triangulate the exact 3D location of a target AP (including which floor of a skyscraper it is on).

### Space-Based SIGINT (LEO Satellite Triangulation)
- **The Concept:** Companies like HawkEye 360 and military defense agencies use clusters of Low Earth Orbit (LEO) satellites to map RF emissions globally.
- **Execution:** 3 satellites fly in a tight triangular formation in space. When a strong Wi-Fi router, maritime radar, or cellular tower transmits a signal on Earth, the satellites capture it. By combining **TDOA** (Time Difference) and **FDOA** (Frequency/Doppler Shift) from the satellite cluster traveling at 7.8 km/s, they can pinpoint the location of a standard Wi-Fi router from outer space.
