/**
 * Which range an address belongs to.
 *
 *     npm run test:cidr
 *
 * Why this exists.
 *
 * `IntrusionPage` answered this by comparing the first three octets as text,
 * which is right for a /24 and wrong for everything else in both directions: a
 * /16 drops every host outside one arbitrary third octet, and a /25 accepts the
 * half of the range that belongs to the other segment. It had not been noticed
 * because the sweep's own subnet list is almost always /24.
 *
 * The segmentation map is not. It carries whatever prefix the engine derived,
 * and the first consumer to be handed one that is not 24 is the host count per
 * VLAN — where a host counted into the wrong range is a factual claim about
 * where a machine sits on somebody's network.
 *
 * So the cases here are the ones a /24 assumption gets wrong, plus the two
 * boundaries that the general formula gets wrong on its own.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';

import { ipToInt, parseCidr, ipInCidr, usableAddresses } from '../.test-build/cidr.mjs';

test('a /24 behaves as the octet comparison did', () => {
  // The case that worked before, which still has to work.
  assert.equal(ipInCidr('192.168.31.17', '192.168.31.0/24'), true);
  assert.equal(ipInCidr('192.168.32.17', '192.168.31.0/24'), false);
});

test('a /16 keeps the hosts the octet comparison threw away', () => {
  /*
    `'172.30.96.0'.split('.').slice(0,3)` is `172.30.96`, so under the old rule a
    host at 172.30.7.4 was not in 172.30.0.0/16. It is.
  */
  assert.equal(ipInCidr('172.30.7.4', '172.30.0.0/16'), true);
  assert.equal(ipInCidr('172.30.255.254', '172.30.0.0/16'), true);
  assert.equal(ipInCidr('172.31.0.1', '172.30.0.0/16'), false);
});

test('a /25 rejects the half that belongs to the other segment', () => {
  /*
    The opposite error, and the more dangerous one: both halves share three
    octets, so the old rule put every host of 192.168.1.128/25 into
    192.168.1.0/25 as well — two different segments merged into one.
  */
  assert.equal(ipInCidr('192.168.1.100', '192.168.1.0/25'), true);
  assert.equal(ipInCidr('192.168.1.200', '192.168.1.0/25'), false);
  assert.equal(ipInCidr('192.168.1.200', '192.168.1.128/25'), true);
  assert.equal(ipInCidr('192.168.1.100', '192.168.1.128/25'), false);
});

test('a /8 holds everything under its first octet', () => {
  assert.equal(ipInCidr('10.20.0.32', '10.0.0.0/8'), true);
  assert.equal(ipInCidr('10.255.255.255', '10.0.0.0/8'), true);
  assert.equal(ipInCidr('11.0.0.1', '10.0.0.0/8'), false);
});

test('a /0 holds every address, without a shift that wraps', () => {
  /*
    `1 << 32` is 1 in JavaScript, not 0, so a mask computed by shifting is wrong
    for /0 specifically — it masks nothing and matches nothing. The two are
    indistinguishable from the outside until the one address that should match
    does not.
  */
  assert.equal(ipInCidr('8.8.8.8', '0.0.0.0/0'), true);
  assert.equal(ipInCidr('192.168.1.1', '0.0.0.0/0'), true);
});

test('a bare address is a range of one', () => {
  // The engine has sent both forms.
  assert.equal(ipInCidr('10.0.0.5', '10.0.0.5'), true);
  assert.equal(ipInCidr('10.0.0.6', '10.0.0.5'), false);
  assert.equal(ipInCidr('10.0.0.5', '10.0.0.5/32'), true);
});

test('the host bits of the given range are ignored', () => {
  // `get_all_subnets` does not promise a network address, and rejecting
  // `192.168.1.57/24` would drop a real segment over how it was spelled.
  assert.equal(ipInCidr('192.168.1.9', '192.168.1.57/24'), true);
  assert.deepEqual(parseCidr('192.168.1.57/24'), parseCidr('192.168.1.0/24'));
});

test('malformed input is false, not a coincidence', () => {
  /*
    `Number('')` is 0 and `Number('1e2')` is 100, so a loose parse turns
    nonsense into a plausible address and answers confidently about it.
  */
  assert.equal(ipToInt(''), null);
  assert.equal(ipToInt('1e2.0.0.1'), null);
  assert.equal(ipToInt('192.168.1'), null);
  assert.equal(ipToInt('192.168.1.256'), null);
  assert.equal(ipToInt('192.168.1.1.1'), null);
  assert.equal(parseCidr('192.168.1.0/33'), null);
  assert.equal(parseCidr('garbage'), null);
  assert.equal(ipInCidr('not an ip', '192.168.1.0/24'), false);
  assert.equal(ipInCidr('192.168.1.1', 'garbage'), false);
});

test('usable addresses, including the two the formula gets wrong', () => {
  assert.equal(usableAddresses(24), 254);
  assert.equal(usableAddresses(16), 65534);
  assert.equal(usableAddresses(25), 126);
  // A point-to-point link has no network or broadcast address, so both are
  // usable; the general rule would say zero. A /32 is one host, not minus one.
  assert.equal(usableAddresses(31), 2);
  assert.equal(usableAddresses(32), 1);
  assert.equal(usableAddresses(33), null);
});
