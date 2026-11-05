# Round 36 stage3: solpro

OI-1: AGREE
OI-2: DISAGREE: With User=monero-wallet, the process starts under that UID before opening --config-file, so open(2) on a root:root 0600 config returns EACCES, verifiable with runuser -u monero-wallet -- test -r <config>.
OI-3: AGREE
OI-4: AGREE
OI-5: AGREE
OI-6: AGREE
OI-7: AGREE
OI-8: AGREE
OI-9: AGREE
OI-10: AGREE
OI-11: AGREE
OI-12: AGREE
OI-13: AGREE
OI-14: AGREE
OI-15: AGREE
OI-16: AGREE
OI-17: AGREE
OI-18: DISAGREE: With capacity C and C unexpired entries, inserting entry C+1 still evicts the oldest fresh entry, so its next request receives a reset window despite expired-first pruning.
OI-19: AGREE
OI-20: AGREE
OI-21: AGREE
OI-22: AGREE
OI-23: AGREE
OI-24: AGREE
OI-25: AGREE
OI-26: AGREE
OI-27: AGREE
OI-28: AGREE
OI-29: AGREE
OI-30: AGREE
OI-31: AGREE
OI-32: AGREE
OI-33: AGREE
OI-34: DISAGREE: If the expected SHA-256 is H1 and current asset bytes hash to H2 where H2 != H1, the proposed runtime branch serves H2 and therefore bypasses the asserted content pin.
OI-35: AGREE
OI-36: AGREE
OI-37: AGREE
OI-38: AGREE
OI-39: AGREE
OI-40: AGREE
OI-41: AGREE
OI-42: AGREE
OI-43: AGREE
OI-44: AGREE
OI-45: AGREE
OI-46: AGREE
OI-47: AGREE
OI-48: AGREE
OI-49: AGREE
OI-50: AGREE

RATIFICATION STATEMENT: OI-2 remains unresolved until a service-start test proves that monero-wallet can read the proposed root:root 0600 configuration; otherwise use systemd credentials or a narrowly readable group-owned file. OI-18 remains unresolved until a capacity test with C+1 unexpired client keys proves that an existing client's window cannot be reset by eviction. OI-34 remains unresolved until a mismatch test proves that bytes with H2 != H1 are rejected, or those bytes carry independently verified signed provenance before service.
