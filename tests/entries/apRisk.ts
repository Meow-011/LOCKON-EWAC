/**
 * Bundle entry for the record-to-rule-set bridge.
 *
 * `apRisk.ts` deliberately does not re-export the rule engine -- it is a bridge
 * to it, not a second door into it -- so the test reaches both through here. The
 * assertion that `isHighRiskAp` *is* the rule set's answer rather than a second
 * opinion about it needs `assessAccessPoint` and `SEVERITY_ORDER` directly, and
 * it has to be the same copy the bridge calls, which one bundle guarantees.
 */
export * from '../../src/lib/apRisk';
export { assessAccessPoint, SEVERITY_ORDER } from '../../src/lib/riskEngine';
