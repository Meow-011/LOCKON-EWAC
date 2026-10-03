/**
 * Does this address sit in that range.
 *
 * Why this is a module rather than three lines where it is needed.
 *
 * `IntrusionPage` already decided this question, by comparing the first three
 * octets as text:
 *
 *     const subnetPrefix = activeSubnet.split('.').slice(0, 3).join('.');
 *     if (!h.ip.startsWith(subnetPrefix)) return false;
 *
 * That is right for a /24 and wrong for everything else, in both directions. A
 * /16 drops every host outside one arbitrary third octet; a /25 accepts the half
 * of the range that belongs to the other segment. The sweep's own subnet list is
 * almost always /24, which is why it has not been noticed — and the segmentation
 * map is not: it carries whatever prefix the engine derived, including the /8
 * and /31 cases its own tests cover.
 *
 * Counting hosts per subnet is the first consumer that will routinely be handed
 * a prefix that is not 24, and a host counted into the wrong VLAN is a factual
 * claim about where a machine sits on the network.
 *
 * IPv4 only, deliberately. Everything upstream of this -- the ARP sweep, the
 * engine's subnet discovery, the PMTiles of this problem -- is IPv4, and a
 * half-written v6 path that silently returns false for a real address would be
 * worse than one that says it cannot answer.
 */

/** A dotted quad as a 32-bit number, or null when it is not one. */
export function ipToInt(ip: string): number | null {
  const parts = String(ip).trim().split('.');
  if (parts.length !== 4) return null;
  let value = 0;
  for (const part of parts) {
    // Rejected rather than coerced: `Number('')` is 0 and `Number('1e2')` is 100,
    // so a loose parse turns malformed input into a plausible address.
    if (!/^\d{1,3}$/.test(part)) return null;
    const n = Number(part);
    if (n > 255) return null;
    value = value * 256 + n;
  }
  return value;
}

export interface ParsedCidr {
  /** The network address, masked, as a 32-bit number. */
  network: number;
  /** Prefix length, 0-32. */
  prefix: number;
}

/**
 * `a.b.c.d/n`, with the host bits cleared.
 *
 * A bare address with no prefix is read as /32 rather than rejected: the engine
 * has sent both forms, and one address is a range of one.
 */
export function parseCidr(cidr: string): ParsedCidr | null {
  const [addr, len] = String(cidr).trim().split('/');
  const base = ipToInt(addr);
  if (base === null) return null;

  const prefix = len === undefined ? 32 : Number(len);
  if (!Number.isInteger(prefix) || prefix < 0 || prefix > 32) return null;

  // `<<` is a 32-bit signed shift in JavaScript and `1 << 32` is 1, not 0, so a
  // /0 computed that way masks nothing. Written as an unsigned subtraction
  // instead, which has no special case.
  const mask = prefix === 0 ? 0 : (0xffffffff << (32 - prefix)) >>> 0;
  return { network: (base & mask) >>> 0, prefix };
}

/** True when `ip` falls inside `cidr`. False for anything unparseable. */
export function ipInCidr(ip: string, cidr: string): boolean {
  const parsed = parseCidr(cidr);
  const value = ipToInt(ip);
  if (!parsed || value === null) return false;
  const mask = parsed.prefix === 0 ? 0 : (0xffffffff << (32 - parsed.prefix)) >>> 0;
  return ((value & mask) >>> 0) === parsed.network;
}

/**
 * How many addresses a host could occupy in this range.
 *
 * The network and broadcast addresses are excluded, which is what makes "2 of
 * 254" the familiar figure for a /24. A /31 is a point-to-point link where both
 * addresses are usable, and a /32 is one host -- the two cases where the general
 * rule gives a negative answer, and where this project has already had to be
 * careful once in `vlan_detect.py`.
 */
export function usableAddresses(prefix: number): number | null {
  if (!Number.isInteger(prefix) || prefix < 0 || prefix > 32) return null;
  if (prefix === 32) return 1;
  if (prefix === 31) return 2;
  return 2 ** (32 - prefix) - 2;
}
