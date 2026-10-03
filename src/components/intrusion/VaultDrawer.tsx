import { motion, AnimatePresence } from 'framer-motion';
import { useState, useEffect, useRef } from 'react';
import {
  getAllCredentials,
  deleteCredential,
  clearAllCredentials,
  getVaultStatus,
  createVault,
  openVault,
  sealLegacyCredentials,
  saveCredential,
  lockVault,
  onVaultLockChange,
  WrongPassphraseError,
  VaultLockedError,
  type StoredCredential,
  type VaultStatus,
} from '../../lib/credentialDB';
import { useIntrusionStore } from '../../stores/intrusionStore';
import { engineIPC } from '../../lib/ipc';
import { ConfirmModal } from '../common/ConfirmModal';

interface VaultDrawerProps {
  isOpen: boolean;
  onClose: () => void;
}

export function VaultDrawer({ isOpen, onClose }: VaultDrawerProps) {
  const [credentials, setCredentials] = useState<StoredCredential[]>([]);
  const [loading, setLoading] = useState(false);
  const [visiblePasswords, setVisiblePasswords] = useState<Record<number, boolean>>({});

  // Vault lock state. The passphrase itself is never stored here beyond the
  // keystrokes needed to derive the key.
  const [vault, setVault] = useState<VaultStatus | null>(null);
  const [passphrase, setPassphrase] = useState('');
  const [passphraseConfirm, setPassphraseConfirm] = useState('');
  const [vaultBusy, setVaultBusy] = useState(false);
  const [vaultError, setVaultError] = useState<string | null>(null);
  const [vaultNotice, setVaultNotice] = useState<string | null>(null);

  // Spray State
  const hosts = useIntrusionStore(s => s.hosts);
  const [sprayState, setSprayState] = useState<'IDLE' | 'SPRAYING' | 'SUCCESS'>('IDLE');
  const [sprayProgress, setSprayProgress] = useState<string>('');
  const [spraySuccesses, setSpraySuccesses] = useState<any[]>([]);
  const [activeSprayId, setActiveSprayId] = useState<number | null>(null);
  const [showClearConfirm, setShowClearConfirm] = useState(false);
  const [sprayUnreachable, setSprayUnreachable] = useState<{ ip: string; port: number; service: string; reason: string }[]>([]);
  const sprayResetTimer = useRef<ReturnType<typeof setTimeout> | null>(null);

  useEffect(() => {
    if (isOpen) {
      loadCredentials();
    }
  }, [isOpen]);

  // A lock or unlock changes what every row can show, so re-read rather than
  // leaving decrypted values on screen after the key is dropped.
  useEffect(() => onVaultLockChange(() => { if (isOpen) loadCredentials(); }), [isOpen]);

  useEffect(() => {
    const unsubStart = engineIPC.on('spray_started', (msg: any) => {
      setSprayState('SPRAYING');
      setSpraySuccesses([]);
      setSprayUnreachable([]);
      setSprayProgress(`Initializing spray against ${msg.data.total_targets} targets...`);
    });
    const unsubProgress = engineIPC.on('spray_progress', (msg: any) => {
      setSprayProgress(`Testing: ${msg.data.target}`);
    });
    const unsubSuccess = engineIPC.on('spray_success', (msg: any) => {
      const d = msg.data || {};
      setSpraySuccesses(prev => [...prev, d]);
      // Store it. This used to reload the list "to show the newly acquired
      // ones" while nothing ever wrote them, so a spray that worked left the
      // vault empty and the finding never reached the report.
      (async () => {
        try {
          // The session, for the same reason as the brute-force writer: a row with
          // no session matches no archive, and the credential vanishes from the report.
          await saveCredential(
            d.ip, d.port, d.service || 'unknown', d.username, d.password, 'spray',
            useIntrusionStore.getState().currentSessionId ?? undefined
          );
        } catch (err) {
          if (err instanceof VaultLockedError) {
            setVaultError(
              `${d.username}@${d.ip}:${d.port} was accepted but NOT stored — the vault is locked. `
              + 'Unlock it and re-run the spray to record it.'
            );
          } else {
            console.error('[VAULT] failed to store sprayed credential', err);
          }
        }
        await loadCredentials();
      })();
    });
    // A host the spray could not reach is not the same as a credential that was
    // rejected. Counting them together made an unreachable subnet look like a
    // clean result, which is exactly the kind of false negative that gets a
    // finding left out of the report.
    const unsubUnreachable = engineIPC.on('spray_unreachable', (msg: any) => {
      const d = msg.data || {};
      setSprayUnreachable(prev => [...prev, {
        ip: d.ip, port: d.port, service: d.service, reason: d.reason || 'unreachable'
      }]);
    });
    const unsubComplete = engineIPC.on('spray_completed', () => {
      setSprayState(prev => prev === 'SPRAYING' ? 'SUCCESS' : prev);
      if (sprayResetTimer.current) clearTimeout(sprayResetTimer.current);
      sprayResetTimer.current = setTimeout(() => {
        sprayResetTimer.current = null;
        setSprayState('IDLE');
      }, 10000); // Reset after 10s
    });
    const unsubError = engineIPC.on('spray_error', (msg: any) => {
      setSprayState('IDLE');
      setActiveSprayId(null);
      setSprayProgress(`Spray error: ${msg?.data?.message ?? 'unknown'}`);
    });

    return () => {
      unsubStart();
      unsubProgress();
      unsubSuccess();
      unsubUnreachable();
      unsubComplete();
      unsubError();
      if (sprayResetTimer.current) clearTimeout(sprayResetTimer.current);
    };
  }, []);

  const loadCredentials = async () => {
    setLoading(true);
    try {
      const [creds, status] = await Promise.all([getAllCredentials(), getVaultStatus()]);
      setCredentials(creds);
      setVault(status);
    } catch (err) {
      console.error('Failed to load credentials', err);
    } finally {
      setLoading(false);
    }
  };

  /** Create the vault on first use, or unlock an existing one. */
  const handleVaultSubmit = async () => {
    setVaultError(null);
    setVaultNotice(null);
    if (!passphrase) {
      setVaultError('Enter a passphrase.');
      return;
    }
    const creating = vault !== null && !vault.exists;
    if (creating && passphrase !== passphraseConfirm) {
      setVaultError('The two passphrases do not match.');
      return;
    }
    setVaultBusy(true);
    try {
      if (creating) {
        await createVault(passphrase);
        setVaultNotice('Vault created. There is no recovery for this passphrase — keep it somewhere you will still have it.');
      } else {
        await openVault(passphrase);
      }
      setPassphrase('');
      setPassphraseConfirm('');
      await loadCredentials();
    } catch (err) {
      setVaultError(
        err instanceof WrongPassphraseError
          ? 'That passphrase does not match this vault.'
          : err instanceof Error ? err.message : String(err)
      );
    } finally {
      setVaultBusy(false);
    }
  };

  const handleLock = () => {
    lockVault();
    setVisiblePasswords({});
    setVaultNotice(null);
  };

  /** Encrypt rows written before the vault had a passphrase. */
  const handleSealLegacy = async () => {
    setVaultError(null);
    setVaultBusy(true);
    try {
      const sealed = await sealLegacyCredentials();
      setVaultNotice(
        sealed === 0
          ? 'Nothing left to seal.'
          : `${sealed} credential(s) encrypted. Their cleartext is gone from the database file.`
      );
      await loadCredentials();
    } catch (err) {
      setVaultError(err instanceof Error ? err.message : String(err));
    } finally {
      setVaultBusy(false);
    }
  };

  const handleDelete = async (id: number) => {
    try {
      await deleteCredential(id);
      await loadCredentials();
    } catch (err) {
      console.error('Failed to delete credential', err);
    }
  };

  const handleClear = async () => {
    try {
      await clearAllCredentials();
      await loadCredentials();
    } catch (err) {
      console.error('Failed to clear credentials', err);
    }
  };

  const togglePasswordVisibility = (id: number) => {
    setVisiblePasswords(prev => ({
      ...prev,
      [id]: !prev[id]
    }));
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
  };

  const handleSpray = (cred: StoredCredential) => {
    // Spraying a secret this session cannot read would put the literal string
    // "null" on the wire against every host in the subnet: a burst of real
    // authentication attempts that proves nothing and pollutes the target's
    // logs with failures the report cannot account for.
    if (cred.password === null) {
      setVaultError(
        cred.decrypt_error
          ? 'That credential could not be decrypted, so it cannot be sprayed.'
          : 'Unlock the vault before spraying — the password for that entry cannot be read right now.'
      );
      return;
    }
    const targetHosts = Object.values(hosts).filter(h => h.open_ports.length > 0);
    const targets: any[] = [];
    
    targetHosts.forEach(h => {
      h.open_ports.forEach(p => {
        if ([21, 22, 80, 443].includes(p.port)) {
          let svc = 'http';
          if (p.port === 22) svc = 'ssh';
          if (p.port === 21) svc = 'ftp';
          
          // Don't spray the host we just compromised with the same service
          if (!(h.ip === cred.target_ip && p.port === cred.port)) {
            targets.push({
              ip: h.ip,
              port: p.port,
              service_type: svc
            });
          }
        }
      });
    });

    if (targets.length === 0) {
      console.warn('[SPRAY] No suitable targets (SSH/FTP/HTTP) found in the current LAN scan');
      return;
    }

    setActiveSprayId(cred.id);
    engineIPC.send('start_spray', {
      username: cred.username,
      password: cred.password,
      targets: targets
    }).catch(console.error);
  };

  return (
    <>
    <AnimatePresence>
      {isOpen && (
        <>
          {/* Backdrop */}
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            onClick={onClose}
            className="fixed inset-0 bg-space-950/60 backdrop-blur-sm z-40"
          />

          {/* Drawer Panel */}
          <motion.div
            initial={{ x: '100%' }}
            animate={{ x: 0 }}
            exit={{ x: '100%' }}
            transition={{ type: 'spring', damping: 25, stiffness: 200 }}
            className="fixed right-0 top-0 bottom-0 w-full md:w-[600px] lg:w-[800px] bg-space-900 border-l border-space-500/30 shadow-2xl z-50 flex flex-col"
          >
            {/* Header */}
            <div className="flex items-center justify-between p-4 border-b border-space-500/20 bg-space-800/50">
              <div className="flex items-center gap-3">
                <svg xmlns="http://www.w3.org/2000/svg" className="w-5 h-5 text-amber-400" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M2 18v3c0 .6.4 1 1 1h4v-3h3v-3h2l1.4-1.4a6.5 6.5 0 1 0-4-4Z"/><circle cx="16.5" cy="7.5" r=".5" fill="currentColor"/></svg>
                <h2 className="text-lg font-bold text-white font-tactical tracking-wider">GLOBAL CREDENTIAL VAULT</h2>
              </div>
              <button 
                onClick={onClose}
                className="p-1 px-2 text-gray-400 hover:text-white rounded bg-space-700/50 hover:bg-risk-critical/80 transition-colors uppercase font-tactical text-xs"
              >
                Close
              </button>
            </div>

            {/* Content Scroll Area */}
            <div className="flex-1 overflow-y-auto p-5">
              {/*
                Vault lock state. This is shown before the list because whether
                the secrets below are readable — and whether new ones can be
                recorded at all — is the first thing the operator needs to know.
              */}
              {vault && (
                <div className={`mb-5 p-3 rounded border ${vault.unlocked ? 'border-neon-500/40 bg-neon-500/5' : 'border-amber-500/40 bg-amber-500/5'}`}>
                  <div className="flex items-center justify-between gap-3">
                    <div className="flex items-center gap-2">
                      <span className={`text-[10px] font-tactical tracking-widest ${vault.unlocked ? 'text-neon-400' : 'text-amber-400'}`}>
                        {!vault.exists ? 'VAULT NOT YET PROTECTED'
                          : vault.unlocked ? 'VAULT UNLOCKED' : 'VAULT LOCKED'}
                      </span>
                      <span className="text-[9px] font-mono text-gray-500">
                        AES-256-GCM · PBKDF2-SHA256
                      </span>
                    </div>
                    {vault.unlocked && (
                      <button
                        onClick={handleLock}
                        className="text-[9px] font-tactical tracking-wider px-2 py-1 rounded border border-space-500/40 text-gray-300 hover:bg-space-700/60"
                      >
                        LOCK NOW
                      </button>
                    )}
                  </div>

                  {!vault.exists && (
                    <p className="mt-2 text-[10px] font-mono text-gray-400 leading-relaxed">
                      Recovered passwords are written to the SQLite file. Set a passphrase and they
                      are encrypted at rest, so a lost laptop does not hand over every credential
                      this audit recovered. There is no recovery: forget it and the secrets are gone.
                    </p>
                  )}

                  {vault.exists && vault.unprotected > 0 && (
                    <div className="mt-2 flex items-center justify-between gap-3">
                      <p className="text-[10px] font-mono text-amber-300 leading-relaxed">
                        {vault.unprotected} secret(s) predate encryption and are still
                        <span className="text-risk-critical"> cleartext on disk</span>
                        {/*
                          Broken out by table, because the two are found in
                          different places by anyone reading the file and the
                          operator should know a cracked WPA passphrase is
                          among them. This count covered `credentials` alone,
                          so the banner could read "protected" while every
                          recovered passphrase sat in cleartext.
                        */}
                        {vault.unprotectedCrackedPasswords > 0 && (
                          <> — {vault.unprotectedCredentials} service credential(s) and{' '}
                          {vault.unprotectedCrackedPasswords} cracked WPA passphrase(s)</>
                        )}
                        .
                      </p>
                      <button
                        onClick={handleSealLegacy}
                        disabled={!vault.unlocked || vaultBusy}
                        className="shrink-0 text-[9px] font-tactical tracking-wider px-2 py-1 rounded border border-amber-500/50 text-amber-300 hover:bg-amber-500/10 disabled:opacity-40"
                        title={vault.unlocked ? 'Encrypt them now' : 'Unlock the vault first'}
                      >
                        SEAL THEM
                      </button>
                    </div>
                  )}

                  {!vault.unlocked && (
                    <div className="mt-3 flex flex-wrap items-center gap-2">
                      <input
                        type="password"
                        value={passphrase}
                        onChange={(e) => setPassphrase(e.target.value)}
                        onKeyDown={(e) => { if (e.key === 'Enter' && vault.exists) handleVaultSubmit(); }}
                        placeholder={vault.exists ? 'Vault passphrase' : 'New passphrase'}
                        autoComplete="off"
                        className="flex-1 min-w-[160px] bg-space-900 border border-space-500/30 rounded px-2 py-1.5 text-xs font-mono text-white placeholder-gray-600 focus:border-neon-500/50 focus:outline-none"
                      />
                      {!vault.exists && (
                        <input
                          type="password"
                          value={passphraseConfirm}
                          onChange={(e) => setPassphraseConfirm(e.target.value)}
                          onKeyDown={(e) => { if (e.key === 'Enter') handleVaultSubmit(); }}
                          placeholder="Confirm"
                          autoComplete="off"
                          className="flex-1 min-w-[120px] bg-space-900 border border-space-500/30 rounded px-2 py-1.5 text-xs font-mono text-white placeholder-gray-600 focus:border-neon-500/50 focus:outline-none"
                        />
                      )}
                      <button
                        onClick={handleVaultSubmit}
                        disabled={vaultBusy}
                        className="text-[10px] font-tactical tracking-wider px-3 py-1.5 rounded border border-neon-500/50 text-neon-300 hover:bg-neon-500/10 disabled:opacity-40"
                      >
                        {vaultBusy ? 'DERIVING KEY…' : vault.exists ? 'UNLOCK' : 'PROTECT VAULT'}
                      </button>
                    </div>
                  )}

                  {vaultError && (
                    <p className="mt-2 text-[10px] font-mono text-risk-critical leading-relaxed">{vaultError}</p>
                  )}
                  {vaultNotice && (
                    <p className="mt-2 text-[10px] font-mono text-neon-300 leading-relaxed">{vaultNotice}</p>
                  )}
                </div>
              )}
              <div className="flex justify-between items-center mb-6">
                <div className="flex items-center gap-4">
                  <div className="text-sm font-mono text-gray-400">
                    <span className="text-white font-bold text-lg">{credentials.length}</span> SECRETS STORED
                  </div>
                  <div className="text-sm font-mono text-gray-400">
                    <span className="text-amber-400 font-bold text-lg">{new Set(credentials.map(c => c.target_ip)).size}</span> COMPROMISED HOSTS
                  </div>
                </div>

                <button 
                  onClick={() => setShowClearConfirm(true)}
                  className="px-3 py-1.5 border border-risk-critical/30 text-risk-critical hover:bg-risk-critical hover:text-white rounded text-xs font-tactical tracking-widest transition-colors"
                >
                  CLEAR VAULT
                </button>
              </div>

              {loading ? (
                <div className="flex justify-center items-center h-32">
                  <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-neon-500"></div>
                </div>
              ) : credentials.length === 0 ? (
                <div className="flex flex-col items-center justify-center h-48 border border-dashed border-space-500/20 rounded-lg">
                  <svg xmlns="http://www.w3.org/2000/svg" className="w-10 h-10 text-gray-600 mb-3" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1"><path d="M21 2l-2 2m-7.61 7.61a5.5 5.5 0 1 1-7.778 7.778 5.5 5.5 0 0 1 7.777-7.777zm0 0L15.5 7.5m0 0l3 3L22 7l-3-3m-3.5 3.5L19 4"></path></svg>
                  <p className="text-gray-500 font-mono text-sm">NO CREDENTIALS ACQUIRED YET</p>
                </div>
              ) : (
                <div className="space-y-3">
                  {credentials.map(cred => (
                    <div key={cred.id} className="bg-space-950/50 border border-space-500/20 rounded-lg p-3 hover:border-amber-500/30 transition-colors group">
                      <div className="flex justify-between items-start mb-2 border-b border-space-500/10 pb-2">
                        <div className="flex items-center gap-3">
                          <span className="text-[10px] px-1.5 py-0.5 rounded bg-space-800 text-amber-400 font-mono border border-amber-500/20">
                            {cred.service.toUpperCase()}
                          </span>
                          <span className="text-sm font-bold text-gray-200 font-mono">
                            {cred.target_ip}:{cred.port}
                          </span>
                          {cred.hostname && <span className="text-xs text-gray-500 font-mono truncate max-w-[150px]">({cred.hostname})</span>}
                        </div>
                        <div className="flex items-center gap-2">
                          <span className="text-[9px] text-gray-500 font-tactical uppercase tracking-wider">
                            SRC: {cred.source.replace('_', ' ')}
                          </span>
                          <button 
                            onClick={() => handleDelete(cred.id)}
                            className="text-gray-600 hover:text-risk-critical transition-colors"
                            title="Delete Entry"
                          >
                            <svg xmlns="http://www.w3.org/2000/svg" className="w-3.5 h-3.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M3 6h18M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/></svg>
                          </button>
                        </div>
                      </div>

                      <div className="grid grid-cols-2 gap-4 mt-3">
                        <div>
                          <div className="text-[10px] text-gray-500 font-mono mb-1">USERNAME</div>
                          <div className="flex items-center gap-2 bg-space-900 border border-space-500/10 px-2 py-1.5 rounded">
                            <span className="text-sm text-gray-300 font-mono flex-1">{cred.username}</span>
                            <button onClick={() => copyToClipboard(cred.username)} className="text-gray-500 hover:text-white" title="Copy">
                              <svg xmlns="http://www.w3.org/2000/svg" className="w-3.5 h-3.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>
                            </button>
                          </div>
                        </div>
                        <div>
                          <div className="text-[10px] text-gray-500 font-mono mb-1 flex items-center gap-2">
                            <span>PASSWORD</span>
                            {/*
                              Which rows are actually protected. A vault that
                              looked uniformly encrypted while some rows were
                              cleartext would be the same kind of untruth as an
                              unflagged simulation.
                            */}
                            {cred.enc_version === 0 && (
                              <span className="text-[8px] px-1 py-0.5 rounded bg-risk-critical/15 text-risk-critical border border-risk-critical/30">
                                CLEARTEXT ON DISK
                              </span>
                            )}
                            {cred.decrypt_error && (
                              <span className="text-[8px] px-1 py-0.5 rounded bg-risk-critical/15 text-risk-critical border border-risk-critical/30">
                                ALTERED — FAILED AUTHENTICATION
                              </span>
                            )}
                          </div>
                          <div className="flex items-center gap-2 bg-space-900 border border-space-500/10 px-2 py-1.5 rounded">
                            <span className={`text-sm font-mono flex-1 truncate ${cred.password === null ? 'text-gray-500' : 'text-white'}`}>
                              {cred.password === null
                                ? (cred.decrypt_error ? 'unreadable' : cred.locked ? 'locked' : 'not stored')
                                : visiblePasswords[cred.id] ? cred.password : '••••••••'}
                            </span>
                            <button onClick={() => togglePasswordVisibility(cred.id)} disabled={cred.password === null} className="text-gray-500 hover:text-white disabled:opacity-30 disabled:hover:text-gray-500" title={cred.password === null ? 'Unlock the vault to read this' : 'Toggle Visibility'}>
                              {visiblePasswords[cred.id] ? (
                                <svg xmlns="http://www.w3.org/2000/svg" className="w-3.5 h-3.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24M1 1l22 22"/></svg>
                              ) : (
                                <svg xmlns="http://www.w3.org/2000/svg" className="w-3.5 h-3.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>
                              )}
                            </button>
                            <button onClick={() => copyToClipboard(cred.password ?? '')} disabled={cred.password === null} className="text-gray-500 hover:text-white disabled:opacity-30 disabled:hover:text-gray-500" title="Copy">
                              <svg xmlns="http://www.w3.org/2000/svg" className="w-3.5 h-3.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>
                            </button>
                          </div>
                        </div>
                      </div>
                      
                      <div className="flex justify-between items-center mt-3">
                        <div className="text-[9px] text-gray-600 font-mono">
                          ACQUIRED: {new Date(cred.discovered_at).toLocaleString()}
                        </div>
                        {cred.session_id && (
                          <div className="text-[9px] text-gray-600 font-mono">
                            SESSION: {cred.session_id}
                          </div>
                        )}
                      </div>

                      {/* Spray Action */}
                      <div className="mt-3 pt-3 border-t border-space-500/10">
                        {sprayState === 'IDLE' || activeSprayId !== cred.id ? (
                          <button 
                            onClick={() => handleSpray(cred)}
                            disabled={sprayState !== 'IDLE' || cred.password === null}
                            title={cred.password === null ? 'Unlock the vault to use this credential' : undefined}
                            className={`w-full py-2 text-xs font-tactical tracking-widest rounded transition-colors flex items-center justify-center gap-2 ${sprayState !== 'IDLE' || cred.password === null ? 'bg-space-800 text-gray-500 cursor-not-allowed' : 'bg-risk-high/10 text-risk-high border border-risk-high/30 hover:bg-risk-high hover:text-white'}`}
                          >
                            <svg xmlns="http://www.w3.org/2000/svg" className="w-4 h-4" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"></path><polyline points="22 4 12 14.01 9 11.01"></polyline></svg>
                            {cred.password === null ? 'VAULT LOCKED' : 'SPRAY ACROSS LAN'}
                          </button>
                        ) : sprayState === 'SPRAYING' ? (
                          <div className="w-full py-2 flex flex-col items-center justify-center gap-2 bg-risk-high border border-risk-high/50 rounded text-sm relative">
                            <button onClick={() => { engineIPC.send('stop_spray').catch(console.error); setSprayState('IDLE'); }} className="absolute top-1 right-1 p-1 text-white/50 hover:text-white">
                              <svg xmlns="http://www.w3.org/2000/svg" className="w-3 h-3" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><line x1="18" y1="6" x2="6" y2="18"></line><line x1="6" y1="6" x2="18" y2="18"></line></svg>
                            </button>
                            <div className="flex items-center gap-2">
                              <svg className="w-4 h-4 text-white animate-spin" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M12 2v4M12 18v4M4.93 4.93l2.83 2.83M16.24 16.24l2.83 2.83M2 12h4M18 12h4M4.93 19.07l2.83-2.83M16.24 7.76l2.83-2.83"/></svg>
                              <span className="text-white font-tactical tracking-widest text-[10px]">SPRAYING CREDENTIALS...</span>
                            </div>
                            <span className="text-white/80 font-mono text-[9px]">{sprayProgress}</span>
                          </div>
                        ) : sprayState === 'SUCCESS' && (
                          <div className="w-full py-2 flex flex-col gap-1 bg-signal-strong/20 border border-signal-strong/50 rounded p-2 relative">
                            <button onClick={() => setSprayState('IDLE')} className="absolute top-1 right-1 p-1 text-signal-strong/50 hover:text-signal-strong">
                              <svg xmlns="http://www.w3.org/2000/svg" className="w-3 h-3" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><line x1="18" y1="6" x2="6" y2="18"></line><line x1="6" y1="6" x2="18" y2="18"></line></svg>
                            </button>
                            <div className="text-signal-strong font-tactical tracking-widest text-[10px]">SPRAY COMPLETE</div>
                            <div className="text-white font-mono text-[10px]">
                              {spraySuccesses.length > 0 ? `Compromised ${spraySuccesses.length} new targets!` : 'No additional targets compromised.'}
                            </div>
                            {/* Unreachable hosts are reported separately: a host
                                that was never contacted has not been shown to be
                                secure, and must not read as a clean result. */}
                            {sprayUnreachable.length > 0 && (
                              <div className="mt-1 pt-1 border-t border-signal-strong/20">
                                <div className="text-risk-high font-mono text-[10px]">
                                  {sprayUnreachable.length} target(s) unreachable — not tested
                                </div>
                                <div className="text-gray-400 font-mono text-[9px] max-h-16 overflow-y-auto mt-0.5">
                                  {sprayUnreachable.map((u, i) => (
                                    <div key={`${u.ip}-${u.port}-${i}`}>{u.ip}:{u.port} ({u.service}) — {u.reason}</div>
                                  ))}
                                </div>
                              </div>
                            )}
                          </div>
                        )}
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </motion.div>
        </>
      )}
    </AnimatePresence>

      <ConfirmModal
        isOpen={showClearConfirm}
        title="CLEAR CREDENTIAL VAULT"
        message="Are you sure you want to clear the entire credential vault? This cannot be undone."
        confirmLabel="CLEAR ALL"
        variant="danger"
        onConfirm={handleClear}
        onCancel={() => setShowClearConfirm(false)}
      />
    </>
  );
}
