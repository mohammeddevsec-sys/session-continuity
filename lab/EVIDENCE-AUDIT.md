# Evidence Audit - Named Checks

Generated from executing each probe listed below. The probe SHA-256 is recorded so that any third party can verify that the probe file has not changed between the run and the audit.

Total checks: 251
Pass: 251
Fail: 0

| # | Probe | Probe SHA-256 (16) | Check | Result | Reason |
|---|-------|--------------------|-------|--------|--------|
| 1 | `PROOF.mjs` | `AAA12410D71AE898` | `V1_RESULT` | PASS |  |
| 2 | `PROOF.mjs` | `AAA12410D71AE898` | `V1_1_RESULT` | PASS |  |
| 3 | `PROOF.mjs` | `AAA12410D71AE898` | `PC1_VALID_SIGNATURE_ACCEPTED` | PASS | PROOF_SIGNATURE_VALID |
| 4 | `PROOF.mjs` | `AAA12410D71AE898` | `PC2_VALID_CHAIN_ACCEPTED` | PASS | CONTINUITY_PROVEN |
| 5 | `PROOF.mjs` | `AAA12410D71AE898` | `NC1_TAMPERED_DECISION_REJECTED` | PASS | SIGNATURE_INVALID |
| 6 | `PROOF.mjs` | `AAA12410D71AE898` | `NC2_TAMPERED_HASH_REJECTED` | PASS | SIGNATURE_INVALID |
| 7 | `PROOF.mjs` | `AAA12410D71AE898` | `NC3_HASH_MISMATCH_REJECTED` | PASS | CONTINUITY_HASH_MISMATCH |
| 8 | `PROOF.mjs` | `AAA12410D71AE898` | `NC4_EMPTY_CHAIN_REJECTED` | PASS | EMPTY_CHAIN |
| 9 | `PROOF.mjs` | `AAA12410D71AE898` | `NC5_MISSING_VERIFIER_REJECTED` | PASS | SIGNATURE_VERIFIER_REQUIRED |
| 10 | `PROOF.mjs` | `AAA12410D71AE898` | `NC6_WRONG_SCHEMA_REJECTED` | PASS | CERTIFICATE_INVALID |
| 11 | `PROOF.mjs` | `AAA12410D71AE898` | `OVERALL` | PASS |  |
| 12 | `_full-audit.mjs` | `D750218CA313C943` | `A_INTEGRITY_ALL` | PASS |  |
| 13 | `_full-audit.mjs` | `D750218CA313C943` | `B_V1_FINAL_REGRESSION` | PASS |  |
| 14 | `_full-audit.mjs` | `D750218CA313C943` | `B_V1_REGRESSION` | PASS |  |
| 15 | `_full-audit.mjs` | `D750218CA313C943` | `C_V1_1_RESULT` | PASS |  |
| 16 | `_full-audit.mjs` | `D750218CA313C943` | `C_V1_1_REGRESSION` | PASS |  |
| 17 | `_full-audit.mjs` | `D750218CA313C943` | `D_RFC8032_PUBLIC_KEY` | PASS |  |
| 18 | `_full-audit.mjs` | `D750218CA313C943` | `D_RFC8032_SIGNATURE` | PASS |  |
| 19 | `_full-audit.mjs` | `D750218CA313C943` | `D_RFC8032_VERIFY` | PASS |  |
| 20 | `_full-audit.mjs` | `D750218CA313C943` | `E_NEGATIVE_ZERO_REJECTED` | PASS |  |
| 21 | `_full-audit.mjs` | `D750218CA313C943` | `E_NAN_REJECTED` | PASS |  |
| 22 | `_full-audit.mjs` | `D750218CA313C943` | `E_INFINITY_REJECTED` | PASS |  |
| 23 | `_full-audit.mjs` | `D750218CA313C943` | `E_LONE_SURROGATE_REJECTED` | PASS |  |
| 24 | `_full-audit.mjs` | `D750218CA313C943` | `E_RECURSIVE_SORT` | PASS |  |
| 25 | `_full-audit.mjs` | `D750218CA313C943` | `F_V1_UTF16_ORDER` | PASS |  |
| 26 | `_full-audit.mjs` | `D750218CA313C943` | `F_V1_V11_AGREE` | PASS |  |
| 27 | `_full-audit.mjs` | `D750218CA313C943` | `G_WITNESS_FIRST` | PASS |  |
| 28 | `_full-audit.mjs` | `D750218CA313C943` | `G_WITNESS_FORK_DETECTED` | PASS |  |
| 29 | `_full-audit.mjs` | `D750218CA313C943` | `G_WITNESS_FORK_HAS_RECEIPT` | PASS |  |
| 30 | `_full-audit.mjs` | `D750218CA313C943` | `G_WITNESS_EQUIVOCATION_PROVEN` | PASS |  |
| 31 | `_full-audit.mjs` | `D750218CA313C943` | `H_ACTIVE_PROOF_VALID` | PASS |  |
| 32 | `_full-audit.mjs` | `D750218CA313C943` | `H_HISTORICAL_RETIRED_VALID` | PASS |  |
| 33 | `_full-audit.mjs` | `D750218CA313C943` | `H_POST_RETIREMENT_REJECTED` | PASS |  |
| 34 | `_full-audit.mjs` | `D750218CA313C943` | `H_COMPROMISE_WINDOW_REJECTED` | PASS |  |
| 35 | `_full-audit.mjs` | `D750218CA313C943` | `H_PRE_COMPROMISE_VALID` | PASS |  |
| 36 | `_full-audit.mjs` | `D750218CA313C943` | `I_CHAIN_5_PROOFS` | PASS |  |
| 37 | `_full-audit.mjs` | `D750218CA313C943` | `I_PACKAGE_VALID` | PASS |  |
| 38 | `_full-audit.mjs` | `D750218CA313C943` | `I_ATTACKER_PROOF_REJECTED` | PASS |  |
| 39 | `_full-audit.mjs` | `D750218CA313C943` | `J_SCALE_1000_VERIFIED` | PASS |  |
| 40 | `_full-audit.mjs` | `D750218CA313C943` | `J_SCALE_BUILD_UNDER_5S` | PASS |  |
| 41 | `_full-audit.mjs` | `D750218CA313C943` | `J_SCALE_VERIFY_UNDER_1S` | PASS |  |
| 42 | `_full-audit.mjs` | `D750218CA313C943` | `K_PACKAGE_NAME_VERSION` | PASS |  |
| 43 | `_full-audit.mjs` | `D750218CA313C943` | `K_PACKAGE_PRIVATE` | PASS |  |
| 44 | `_full-audit.mjs` | `D750218CA313C943` | `FULL_AUDIT` | PASS |  |
| 45 | `v1_1-regression-gate.mjs` | `7F768D6C0CD52A69` | `PROBE::v1_1-integration-probe.mjs` | PASS |  |
| 46 | `v1_1-regression-gate.mjs` | `7F768D6C0CD52A69` | `PROBE::v1_1-chain-probe.mjs` | PASS |  |
| 47 | `v1_1-regression-gate.mjs` | `7F768D6C0CD52A69` | `PROBE::v1_1-scale-chain-probe.mjs` | PASS |  |
| 48 | `v1_1-regression-gate.mjs` | `7F768D6C0CD52A69` | `PROBE::v1_1-trusted-chain-probe.mjs` | PASS |  |
| 49 | `v1_1-regression-gate.mjs` | `7F768D6C0CD52A69` | `PROBE::v1_1-sequence-guard-probe.mjs` | PASS |  |
| 50 | `v1_1-regression-gate.mjs` | `7F768D6C0CD52A69` | `PROBE::v1_1-durable-sequence-probe.mjs` | PASS |  |
| 51 | `v1_1-regression-gate.mjs` | `7F768D6C0CD52A69` | `PROBE::v1_1-witness-probe-v2.mjs` | PASS |  |
| 52 | `v1_1-regression-gate.mjs` | `7F768D6C0CD52A69` | `PROBE::v1_1-witness-fail-closed-probe.mjs` | PASS |  |
| 53 | `v1_1-regression-gate.mjs` | `7F768D6C0CD52A69` | `PROBE::v1_1-portable-package-probe-v2.mjs` | PASS |  |
| 54 | `v1_1-regression-gate.mjs` | `7F768D6C0CD52A69` | `PROBE::v1_1-full-integration-probe.mjs` | PASS |  |
| 55 | `v1_1-regression-gate.mjs` | `7F768D6C0CD52A69` | `PROBE::v1_1-key-lifecycle-probe.mjs` | PASS |  |
| 56 | `v1_1-regression-gate.mjs` | `7F768D6C0CD52A69` | `PROBE::v1_1-lifecycle-integration-probe.mjs` | PASS |  |
| 57 | `v1_1-regression-gate.mjs` | `7F768D6C0CD52A69` | `V1_1_REGRESSION` | PASS |  |
| 58 | `v1_1-integration-probe.mjs` | `7E5D75E73C4FB49F` | `IDENTITY_CREATED` | PASS |  |
| 59 | `v1_1-integration-probe.mjs` | `7E5D75E73C4FB49F` | `ROOT_CREATED` | PASS |  |
| 60 | `v1_1-integration-probe.mjs` | `7E5D75E73C4FB49F` | `CORE_CREATED` | PASS |  |
| 61 | `v1_1-integration-probe.mjs` | `7E5D75E73C4FB49F` | `HASH_ADDED` | PASS |  |
| 62 | `v1_1-integration-probe.mjs` | `7E5D75E73C4FB49F` | `SIGNED` | PASS |  |
| 63 | `v1_1-integration-probe.mjs` | `7E5D75E73C4FB49F` | `VERIFIED` | PASS |  |
| 64 | `v1_1-chain-probe.mjs` | `13171C3E12FB91DC` | `CHAIN_VERIFY` | PASS |  |
| 65 | `v1_1-chain-probe.mjs` | `13171C3E12FB91DC` | `CHAIN_HEAD` | PASS |  |
| 66 | `v1_1-chain-probe.mjs` | `13171C3E12FB91DC` | `TAMPER_REJECTED` | PASS |  |
| 67 | `v1_1-chain-probe.mjs` | `13171C3E12FB91DC` | `WRONG_PARENT_REJECTED` | PASS |  |
| 68 | `v1_1-chain-probe.mjs` | `13171C3E12FB91DC` | `SEQUENCE_GAP_REJECTED` | PASS |  |
| 69 | `v1_1-chain-probe.mjs` | `13171C3E12FB91DC` | `WRONG_ROOT_REJECTED` | PASS |  |
| 70 | `v1_1-chain-probe.mjs` | `13171C3E12FB91DC` | `SINGLE_SIGNATURE` | PASS |  |
| 71 | `v1_1-scale-chain-probe.mjs` | `C9CA5E0AF62DF0D5` | `VERIFIED` | PASS |  |
| 72 | `v1_1-scale-chain-probe.mjs` | `C9CA5E0AF62DF0D5` | `HEAD_MATCH` | PASS |  |
| 73 | `v1_1-trusted-chain-probe.mjs` | `AB03B5DDFDBCF02D` | `LEGIT_TRUSTED_CHAIN` | PASS |  |
| 74 | `v1_1-trusted-chain-probe.mjs` | `AB03B5DDFDBCF02D` | `LEGIT_HEAD_MATCH` | PASS |  |
| 75 | `v1_1-trusted-chain-probe.mjs` | `AB03B5DDFDBCF02D` | `ATTACKER_CHAIN_REJECTED` | PASS |  |
| 76 | `v1_1-trusted-chain-probe.mjs` | `AB03B5DDFDBCF02D` | `NULL_STORE_REJECTED` | PASS |  |
| 77 | `v1_1-trusted-chain-probe.mjs` | `AB03B5DDFDBCF02D` | `EMPTY_CHAIN_REJECTED` | PASS |  |
| 78 | `v1_1-trusted-chain-probe.mjs` | `AB03B5DDFDBCF02D` | `WRONG_ROOT_REJECTED` | PASS |  |
| 79 | `v1_1-trusted-chain-probe.mjs` | `AB03B5DDFDBCF02D` | `REVOKED_SIGNER_REJECTED` | PASS |  |
| 80 | `v1_1-sequence-guard-probe.mjs` | `8404094B0968236E` | `FRESH_SEQ1` | PASS |  |
| 81 | `v1_1-sequence-guard-probe.mjs` | `8404094B0968236E` | `SEQ2_AFTER_1` | PASS |  |
| 82 | `v1_1-sequence-guard-probe.mjs` | `8404094B0968236E` | `STATE_AFTER_2` | PASS |  |
| 83 | `v1_1-sequence-guard-probe.mjs` | `8404094B0968236E` | `SEQ_GAP_DECISION` | PASS |  |
| 84 | `v1_1-sequence-guard-probe.mjs` | `8404094B0968236E` | `STATE_AFTER_GAP` | PASS |  |
| 85 | `v1_1-sequence-guard-probe.mjs` | `8404094B0968236E` | `SEQ_REPLAY_STATE` | PASS |  |
| 86 | `v1_1-sequence-guard-probe.mjs` | `8404094B0968236E` | `SEQ3_AFTER_2` | PASS |  |
| 87 | `v1_1-sequence-guard-probe.mjs` | `8404094B0968236E` | `STATE_AFTER_3` | PASS |  |
| 88 | `v1_1-sequence-guard-probe.mjs` | `8404094B0968236E` | `SEQ4_AFTER_3` | PASS |  |
| 89 | `v1_1-durable-sequence-probe.mjs` | `62C83E94CDC5121E` | `INITIAL_VERIFY` | PASS |  |
| 90 | `v1_1-durable-sequence-probe.mjs` | `62C83E94CDC5121E` | `SEQ1` | PASS |  |
| 91 | `v1_1-durable-sequence-probe.mjs` | `62C83E94CDC5121E` | `SEQ2` | PASS |  |
| 92 | `v1_1-durable-sequence-probe.mjs` | `62C83E94CDC5121E` | `SEQ3` | PASS |  |
| 93 | `v1_1-durable-sequence-probe.mjs` | `62C83E94CDC5121E` | `SEQ_GAP_REJECTED` | PASS |  |
| 94 | `v1_1-durable-sequence-probe.mjs` | `62C83E94CDC5121E` | `SEQ_ROLLBACK_REJECTED` | PASS |  |
| 95 | `v1_1-durable-sequence-probe.mjs` | `62C83E94CDC5121E` | `SEQ_REPLAY_REJECTED` | PASS |  |
| 96 | `v1_1-durable-sequence-probe.mjs` | `62C83E94CDC5121E` | `STATE_AFTER_REJECT` | PASS |  |
| 97 | `v1_1-durable-sequence-probe.mjs` | `62C83E94CDC5121E` | `RESTART_VERIFY` | PASS |  |
| 98 | `v1_1-durable-sequence-probe.mjs` | `62C83E94CDC5121E` | `RESTART_LAST` | PASS |  |
| 99 | `v1_1-durable-sequence-probe.mjs` | `62C83E94CDC5121E` | `RESTART_JOURNAL_HEIGHT` | PASS |  |
| 100 | `v1_1-durable-sequence-probe.mjs` | `62C83E94CDC5121E` | `POST_RESTART_SEQ4` | PASS |  |
| 101 | `v1_1-durable-sequence-probe.mjs` | `62C83E94CDC5121E` | `POST_RESTART_REPLAY` | PASS |  |
| 102 | `v1_1-durable-sequence-probe.mjs` | `62C83E94CDC5121E` | `SECOND_SESSION_SEQ1` | PASS |  |
| 103 | `v1_1-durable-sequence-probe.mjs` | `62C83E94CDC5121E` | `SECOND_SESSION_SEQ2` | PASS |  |
| 104 | `v1_1-durable-sequence-probe.mjs` | `62C83E94CDC5121E` | `SESSION1_INDEPENDENT` | PASS |  |
| 105 | `v1_1-durable-sequence-probe.mjs` | `62C83E94CDC5121E` | `SESSION2_INDEPENDENT` | PASS |  |
| 106 | `v1_1-durable-sequence-probe.mjs` | `62C83E94CDC5121E` | `ROLLBACK_DETECTED` | PASS |  |
| 107 | `v1_1-durable-sequence-probe.mjs` | `62C83E94CDC5121E` | `CORRUPTION_DETECTED` | PASS |  |
| 108 | `v1_1-durable-sequence-probe.mjs` | `62C83E94CDC5121E` | `RECOVERY_AFTER_REPAIR` | PASS |  |
| 109 | `v1_1-durable-sequence-probe.mjs` | `62C83E94CDC5121E` | `RECOVERED_LAST` | PASS |  |
| 110 | `v1_1-durable-sequence-probe.mjs` | `62C83E94CDC5121E` | `PROBE_CLEANUP` | PASS |  |
| 111 | `v1_1-witness-probe-v2.mjs` | `CD3082A01778769D` | `SEQ1_ADVANCED` | PASS |  |
| 112 | `v1_1-witness-probe-v2.mjs` | `CD3082A01778769D` | `HEAD_AFTER_3` | PASS |  |
| 113 | `v1_1-witness-probe-v2.mjs` | `CD3082A01778769D` | `SEQ1_REPLAY` | PASS |  |
| 114 | `v1_1-witness-probe-v2.mjs` | `CD3082A01778769D` | `SEQ2_REPLAY_AFTER_HEAD3` | PASS |  |
| 115 | `v1_1-witness-probe-v2.mjs` | `CD3082A01778769D` | `SEQ1_EQUIVOCATION` | PASS |  |
| 116 | `v1_1-witness-probe-v2.mjs` | `CD3082A01778769D` | `SEQ1_EQUIVOCATION_HAS_RECEIPT` | PASS |  |
| 117 | `v1_1-witness-probe-v2.mjs` | `CD3082A01778769D` | `HEAD_UNCHANGED_AFTER_FORK` | PASS |  |
| 118 | `v1_1-witness-probe-v2.mjs` | `CD3082A01778769D` | `FORK_RECEIPT_VERIFY` | PASS |  |
| 119 | `v1_1-witness-probe-v2.mjs` | `CD3082A01778769D` | `FORK_RECEIPT_SEQ` | PASS |  |
| 120 | `v1_1-witness-probe-v2.mjs` | `CD3082A01778769D` | `FORK_RECEIPT_HASH` | PASS |  |
| 121 | `v1_1-witness-probe-v2.mjs` | `CD3082A01778769D` | `FORK_RECEIPT_HEAD_SEQ` | PASS |  |
| 122 | `v1_1-witness-probe-v2.mjs` | `CD3082A01778769D` | `SAME_DOMAIN_EQUIVOCATION` | PASS |  |
| 123 | `v1_1-witness-probe-v2.mjs` | `CD3082A01778769D` | `CLEANUP` | PASS |  |
| 124 | `v1_1-witness-fail-closed-probe.mjs` | `12560BB48D0A7959` | `SEQ1` | PASS |  |
| 125 | `v1_1-witness-fail-closed-probe.mjs` | `12560BB48D0A7959` | `SEQ2` | PASS |  |
| 126 | `v1_1-witness-fail-closed-probe.mjs` | `12560BB48D0A7959` | `HEALTH_BEFORE_OK` | PASS |  |
| 127 | `v1_1-witness-fail-closed-probe.mjs` | `12560BB48D0A7959` | `HEALTH_CORRUPT_FAIL_CLOSED` | PASS |  |
| 128 | `v1_1-witness-fail-closed-probe.mjs` | `12560BB48D0A7959` | `HEALTH_CORRUPT_REASON_HAS_TAG` | PASS |  |
| 129 | `v1_1-witness-fail-closed-probe.mjs` | `12560BB48D0A7959` | `OBSERVE_REJECTED_WHEN_CORRUPT` | PASS |  |
| 130 | `v1_1-witness-fail-closed-probe.mjs` | `12560BB48D0A7959` | `HEALTH_WRONG_SCHEMA_FAIL_CLOSED` | PASS |  |
| 131 | `v1_1-witness-fail-closed-probe.mjs` | `12560BB48D0A7959` | `HEALTH_RESTORED_OK` | PASS |  |
| 132 | `v1_1-witness-fail-closed-probe.mjs` | `12560BB48D0A7959` | `RESUMED_AFTER_RESTORE` | PASS |  |
| 133 | `v1_1-witness-fail-closed-probe.mjs` | `12560BB48D0A7959` | `CLEANUP` | PASS |  |
| 134 | `v1_1-portable-package-probe-v2.mjs` | `C30031CDD6D81797` | `GOOD_PKG` | PASS |  |
| 135 | `v1_1-portable-package-probe-v2.mjs` | `C30031CDD6D81797` | `TAMPERED_PROOF_DEEP_REJECTED` | PASS |  |
| 136 | `v1_1-portable-package-probe-v2.mjs` | `C30031CDD6D81797` | `UNDECLARED_SIGNER_DEEP_REJECTED` | PASS |  |
| 137 | `v1_1-portable-package-probe-v2.mjs` | `C30031CDD6D81797` | `TAMPERED_RECEIPT_DEEP_REJECTED` | PASS |  |
| 138 | `v1_1-portable-package-probe-v2.mjs` | `C30031CDD6D81797` | `RECEIPT_BINDING_DEEP_REJECTED` | PASS |  |
| 139 | `v1_1-portable-package-probe-v2.mjs` | `C30031CDD6D81797` | `FAKE_PACKAGER_REJECTED` | PASS |  |
| 140 | `v1_1-portable-package-probe-v2.mjs` | `C30031CDD6D81797` | `NO_RECEIPTS_ACCEPTED` | PASS |  |
| 141 | `v1_1-portable-package-probe-v2.mjs` | `C30031CDD6D81797` | `WRONG_ROOT_DEEP_REJECTED` | PASS |  |
| 142 | `v1_1-portable-package-probe-v2.mjs` | `C30031CDD6D81797` | `CLEANUP` | PASS |  |
| 143 | `v1_1-full-integration-probe.mjs` | `1CD85A7F5036AF72` | `SEQ_1` | PASS |  |
| 144 | `v1_1-full-integration-probe.mjs` | `1CD85A7F5036AF72` | `SEQ_2` | PASS |  |
| 145 | `v1_1-full-integration-probe.mjs` | `1CD85A7F5036AF72` | `SEQ_3` | PASS |  |
| 146 | `v1_1-full-integration-probe.mjs` | `1CD85A7F5036AF72` | `SEQ_VERIFY` | PASS |  |
| 147 | `v1_1-full-integration-probe.mjs` | `1CD85A7F5036AF72` | `SEQ_HEAD` | PASS |  |
| 148 | `v1_1-full-integration-probe.mjs` | `1CD85A7F5036AF72` | `WITNESS_R1` | PASS |  |
| 149 | `v1_1-full-integration-probe.mjs` | `1CD85A7F5036AF72` | `WITNESS_R2` | PASS |  |
| 150 | `v1_1-full-integration-probe.mjs` | `1CD85A7F5036AF72` | `WITNESS_R3` | PASS |  |
| 151 | `v1_1-full-integration-probe.mjs` | `1CD85A7F5036AF72` | `TRUSTED_CHAIN` | PASS |  |
| 152 | `v1_1-full-integration-probe.mjs` | `1CD85A7F5036AF72` | `PACKAGE_VALID` | PASS |  |
| 153 | `v1_1-full-integration-probe.mjs` | `1CD85A7F5036AF72` | `PACKAGE_CHAIN_LEN` | PASS |  |
| 154 | `v1_1-full-integration-probe.mjs` | `1CD85A7F5036AF72` | `PACKAGE_RECEIPTS_LEN` | PASS |  |
| 155 | `v1_1-full-integration-probe.mjs` | `1CD85A7F5036AF72` | `TAMPER_PROOF_REJECTED` | PASS |  |
| 156 | `v1_1-full-integration-probe.mjs` | `1CD85A7F5036AF72` | `TAMPER_PROOF_LAYER_CORRECT` | PASS |  |
| 157 | `v1_1-full-integration-probe.mjs` | `1CD85A7F5036AF72` | `TAMPER_RECEIPT_REJECTED` | PASS |  |
| 158 | `v1_1-full-integration-probe.mjs` | `1CD85A7F5036AF72` | `TAMPER_RECEIPT_LAYER_CORRECT` | PASS |  |
| 159 | `v1_1-full-integration-probe.mjs` | `1CD85A7F5036AF72` | `FAKE_PACKAGER_REJECTED` | PASS |  |
| 160 | `v1_1-full-integration-probe.mjs` | `1CD85A7F5036AF72` | `FAKE_PACKAGER_LAYER_CORRECT` | PASS |  |
| 161 | `v1_1-full-integration-probe.mjs` | `1CD85A7F5036AF72` | `UNDECLARED_SIGNER_REJECTED` | PASS |  |
| 162 | `v1_1-full-integration-probe.mjs` | `1CD85A7F5036AF72` | `UNDECLARED_SIGNER_LAYER_CORRECT` | PASS |  |
| 163 | `v1_1-full-integration-probe.mjs` | `1CD85A7F5036AF72` | `WITNESS_RESTART_IDEMPOTENT` | PASS |  |
| 164 | `v1_1-full-integration-probe.mjs` | `1CD85A7F5036AF72` | `SEQ_RESTART_VERIFY` | PASS |  |
| 165 | `v1_1-full-integration-probe.mjs` | `1CD85A7F5036AF72` | `SEQ_RESTART_HEAD` | PASS |  |
| 166 | `v1_1-full-integration-probe.mjs` | `1CD85A7F5036AF72` | `SEQ_POST_RESTART_4` | PASS |  |
| 167 | `v1_1-full-integration-probe.mjs` | `1CD85A7F5036AF72` | `CLEANUP` | PASS |  |
| 168 | `v1_1-key-lifecycle-probe.mjs` | `D9A010C51C6F4DE5` | `REGISTER_A_STATUS` | PASS |  |
| 169 | `v1_1-key-lifecycle-probe.mjs` | `D9A010C51C6F4DE5` | `REGISTER_A_FP` | PASS |  |
| 170 | `v1_1-key-lifecycle-probe.mjs` | `D9A010C51C6F4DE5` | `REGISTER_B` | PASS |  |
| 171 | `v1_1-key-lifecycle-probe.mjs` | `D9A010C51C6F4DE5` | `REGISTER_C` | PASS |  |
| 172 | `v1_1-key-lifecycle-probe.mjs` | `D9A010C51C6F4DE5` | `DUPLICATE_REJECTED` | PASS |  |
| 173 | `v1_1-key-lifecycle-probe.mjs` | `D9A010C51C6F4DE5` | `CAN_SIGN_A_NOW` | PASS |  |
| 174 | `v1_1-key-lifecycle-probe.mjs` | `D9A010C51C6F4DE5` | `CAN_SIGN_BEFORE_VALID` | PASS |  |
| 175 | `v1_1-key-lifecycle-probe.mjs` | `D9A010C51C6F4DE5` | `CAN_SIGN_AFTER_VALID` | PASS |  |
| 176 | `v1_1-key-lifecycle-probe.mjs` | `D9A010C51C6F4DE5` | `CAN_SIGN_UNKNOWN` | PASS |  |
| 177 | `v1_1-key-lifecycle-probe.mjs` | `D9A010C51C6F4DE5` | `PROOF_A_VALID` | PASS |  |
| 178 | `v1_1-key-lifecycle-probe.mjs` | `D9A010C51C6F4DE5` | `PROOF_BEFORE_VALID_REJECTED` | PASS |  |
| 179 | `v1_1-key-lifecycle-probe.mjs` | `D9A010C51C6F4DE5` | `PROOF_AFTER_VALID_REJECTED` | PASS |  |
| 180 | `v1_1-key-lifecycle-probe.mjs` | `D9A010C51C6F4DE5` | `RETIRE_B_STATUS` | PASS |  |
| 181 | `v1_1-key-lifecycle-probe.mjs` | `D9A010C51C6F4DE5` | `CAN_SIGN_RETIRED` | PASS |  |
| 182 | `v1_1-key-lifecycle-probe.mjs` | `D9A010C51C6F4DE5` | `HISTORICAL_PROOF_BEFORE_RETIRE` | PASS |  |
| 183 | `v1_1-key-lifecycle-probe.mjs` | `D9A010C51C6F4DE5` | `PROOF_AFTER_RETIRE_REJECTED` | PASS |  |
| 184 | `v1_1-key-lifecycle-probe.mjs` | `D9A010C51C6F4DE5` | `RETIRE_TWICE_REJECTED` | PASS |  |
| 185 | `v1_1-key-lifecycle-probe.mjs` | `D9A010C51C6F4DE5` | `REVOKE_C_STATUS` | PASS |  |
| 186 | `v1_1-key-lifecycle-probe.mjs` | `D9A010C51C6F4DE5` | `REVOKE_C_HAS_WINDOW` | PASS |  |
| 187 | `v1_1-key-lifecycle-probe.mjs` | `D9A010C51C6F4DE5` | `CAN_SIGN_REVOKED` | PASS |  |
| 188 | `v1_1-key-lifecycle-probe.mjs` | `D9A010C51C6F4DE5` | `PROOF_BEFORE_COMPROMISE_VALID` | PASS |  |
| 189 | `v1_1-key-lifecycle-probe.mjs` | `D9A010C51C6F4DE5` | `PROOF_WITHIN_COMPROMISE_REJECTED` | PASS |  |
| 190 | `v1_1-key-lifecycle-probe.mjs` | `D9A010C51C6F4DE5` | `PROOF_AT_COMPROMISE_END_REJECTED` | PASS |  |
| 191 | `v1_1-key-lifecycle-probe.mjs` | `D9A010C51C6F4DE5` | `REVOKE_TWICE_REJECTED` | PASS |  |
| 192 | `v1_1-key-lifecycle-probe.mjs` | `D9A010C51C6F4DE5` | `RETIRE_REVOKED_REJECTED` | PASS |  |
| 193 | `v1_1-key-lifecycle-probe.mjs` | `D9A010C51C6F4DE5` | `GET_KEY_A` | PASS |  |
| 194 | `v1_1-key-lifecycle-probe.mjs` | `D9A010C51C6F4DE5` | `GET_KEY_UNKNOWN` | PASS |  |
| 195 | `v1_1-key-lifecycle-probe.mjs` | `D9A010C51C6F4DE5` | `UNKNOWN_REVOKE_REJECTED` | PASS |  |
| 196 | `v1_1-lifecycle-integration-probe.mjs` | `4A87EEABFCE2D80D` | `GOOD_CHAIN_WITH_LIFECYCLE` | PASS |  |
| 197 | `v1_1-lifecycle-integration-probe.mjs` | `4A87EEABFCE2D80D` | `NO_LIFECYCLE_STORE_REJECTED` | PASS |  |
| 198 | `v1_1-lifecycle-integration-probe.mjs` | `4A87EEABFCE2D80D` | `UNREGISTERED_KEY_REJECTED` | PASS |  |
| 199 | `v1_1-lifecycle-integration-probe.mjs` | `4A87EEABFCE2D80D` | `POST_RETIREMENT_PROOF_REJECTED` | PASS |  |
| 200 | `v1_1-lifecycle-integration-probe.mjs` | `4A87EEABFCE2D80D` | `REQUIRE_ACTIVE_NOW_REJECTED` | PASS |  |
| 201 | `v1_1-lifecycle-integration-probe.mjs` | `4A87EEABFCE2D80D` | `COMPROMISE_WINDOW_PROOF_REJECTED` | PASS |  |
| 202 | `v1_1-lifecycle-integration-probe.mjs` | `4A87EEABFCE2D80D` | `CLEANUP` | PASS |  |
| 203 | `v1_1-oidc-adapter-probe.mjs` | `887A20A45D9876CC` | `OIDC_ANCHOR` | PASS |  |
| 204 | `v1_1-oidc-adapter-probe.mjs` | `887A20A45D9876CC` | `OIDC_BOOTSTRAP` | PASS |  |
| 205 | `v1_1-oidc-adapter-probe.mjs` | `887A20A45D9876CC` | `OIDC_INVALID_CLAIMS` | PASS |  |
| 206 | `v1_1-witness-atomic-receipt-probe.mjs` | `A104170478C6CEC8` | `FIRST_ADVANCED` | PASS |  |
| 207 | `v1_1-witness-atomic-receipt-probe.mjs` | `A104170478C6CEC8` | `RECEIPT_SAVED_WITH_HEAD` | PASS |  |
| 208 | `v1_1-witness-atomic-receipt-probe.mjs` | `A104170478C6CEC8` | `SAVED_RECEIPT_MATCHES_RETURNED` | PASS |  |
| 209 | `v1_1-witness-atomic-receipt-probe.mjs` | `A104170478C6CEC8` | `SAVED_RECEIPT_VERIFIES` | PASS |  |
| 210 | `v1_1-witness-atomic-receipt-probe.mjs` | `A104170478C6CEC8` | `RESTART_REPLAY_IDEMPOTENT` | PASS |  |
| 211 | `v1_1-witness-atomic-receipt-probe.mjs` | `A104170478C6CEC8` | `REPLAY_RECEIPT_IDENTICAL` | PASS |  |
| 212 | `v1_1-witness-atomic-receipt-probe.mjs` | `A104170478C6CEC8` | `HEAD_STABLE_AFTER_RESTART` | PASS |  |
| 213 | `v1_1-witness-crash-boundary-probe.mjs` | `AB9E1C9D39D7EFF8` | `AFTER_WRITE` | PASS |  |
| 214 | `v1_1-witness-crash-boundary-probe.mjs` | `AB9E1C9D39D7EFF8` | `AFTER_FSYNC` | PASS |  |
| 215 | `v1_1-witness-crash-boundary-probe.mjs` | `AB9E1C9D39D7EFF8` | `AFTER_CLOSE` | PASS |  |
| 216 | `v1_1-witness-crash-boundary-probe.mjs` | `AB9E1C9D39D7EFF8` | `AFTER_RENAME` | PASS |  |
| 217 | `continuity-proof-v1_1-p0-critical-gaps.mjs` | `C3D40E7F1A3E2DF6` | `PROPERTY_SORT` | PASS |  |
| 218 | `continuity-proof-v1_1-p0-critical-gaps.mjs` | `C3D40E7F1A3E2DF6` | `RECURSIVE_OBJECT_SORT` | PASS |  |
| 219 | `continuity-proof-v1_1-p0-critical-gaps.mjs` | `C3D40E7F1A3E2DF6` | `NEGATIVE_ZERO_REJECTION` | PASS |  |
| 220 | `continuity-proof-v1_1-p0-critical-gaps.mjs` | `C3D40E7F1A3E2DF6` | `NAN_REJECTION` | PASS |  |
| 221 | `continuity-proof-v1_1-p0-critical-gaps.mjs` | `C3D40E7F1A3E2DF6` | `LONE_SURROGATE_REJECTION` | PASS |  |
| 222 | `continuity-proof-v1_1-p0-critical-gaps.mjs` | `C3D40E7F1A3E2DF6` | `JCS_PROFILE_V1_1` | PASS |  |
| 223 | `continuity-proof-v1_1-p0-critical-gaps.mjs` | `C3D40E7F1A3E2DF6` | `TRUNCATION_PREFIX_ONLY` | PASS |  |
| 224 | `continuity-proof-v1_1-p0-critical-gaps.mjs` | `C3D40E7F1A3E2DF6` | `CHECKPOINT_FINALITY_SCOPE` | PASS |  |
| 225 | `continuity-proof-v1_1-p0-critical-gaps.mjs` | `C3D40E7F1A3E2DF6` | `CHECKPOINT_DOES_NOT_REPLACE_PARENT_CHAIN` | PASS |  |
| 226 | `continuity-proof-v1_1-p0-critical-gaps.mjs` | `C3D40E7F1A3E2DF6` | `CHECKPOINT_TAMPER_REJECTED` | PASS |  |
| 227 | `continuity-proof-v1_1-p0-critical-gaps.mjs` | `C3D40E7F1A3E2DF6` | `TRUE_WITNESS_EQUIVOCATION_EVIDENCE` | PASS |  |
| 228 | `continuity-proof-v1_1-p0-critical-gaps.mjs` | `C3D40E7F1A3E2DF6` | `WITNESS_EQUIVOCATION_IS_EXTERNALLY_PROVABLE` | PASS |  |
| 229 | `continuity-proof-v1_1-p0-critical-gaps.mjs` | `C3D40E7F1A3E2DF6` | `PRE_COMPROMISE_HISTORICAL_PROOF` | PASS |  |
| 230 | `continuity-proof-v1_1-p0-critical-gaps.mjs` | `C3D40E7F1A3E2DF6` | `POST_COMPROMISE_POLICY_DISPOSITION` | PASS |  |
| 231 | `continuity-proof-v1_1-p0-critical-gaps.mjs` | `C3D40E7F1A3E2DF6` | `NEW_KEY_AFTER_ROTATION` | PASS |  |
| 232 | `continuity-proof-v1_1-p0-critical-gaps.mjs` | `C3D40E7F1A3E2DF6` | `REAL_KEY_IDENTITY_SEPARATION` | PASS |  |
| 233 | `continuity-proof-v1_1-p0-critical-gaps.mjs` | `C3D40E7F1A3E2DF6` | `POLICY_FINGERPRINT_BOUND_IN_PROOF` | PASS |  |
| 234 | `continuity-proof-v1_1-p0-critical-gaps.mjs` | `C3D40E7F1A3E2DF6` | `REFERENCE_P0` | PASS |  |
| 235 | `continuity-proof-v1_1-reconciled-integration.mjs` | `61A4D549F0DD9730` | `PROPERTY_SORT` | PASS |  |
| 236 | `continuity-proof-v1_1-reconciled-integration.mjs` | `61A4D549F0DD9730` | `RECURSIVE_OBJECT_SORT` | PASS |  |
| 237 | `continuity-proof-v1_1-reconciled-integration.mjs` | `61A4D549F0DD9730` | `NEGATIVE_ZERO_REJECTION` | PASS |  |
| 238 | `continuity-proof-v1_1-reconciled-integration.mjs` | `61A4D549F0DD9730` | `NAN_REJECTION` | PASS |  |
| 239 | `continuity-proof-v1_1-reconciled-integration.mjs` | `61A4D549F0DD9730` | `LONE_SURROGATE_REJECTION` | PASS |  |
| 240 | `continuity-proof-v1_1-reconciled-integration.mjs` | `61A4D549F0DD9730` | `JCS_PROFILE_V1_1` | PASS |  |
| 241 | `continuity-proof-v1_1-reconciled-integration.mjs` | `61A4D549F0DD9730` | `POLICY_FINGERPRINT_BOUND` | PASS |  |
| 242 | `continuity-proof-v1_1-reconciled-integration.mjs` | `61A4D549F0DD9730` | `PREFIX_VALID_WITHOUT_FINALITY` | PASS |  |
| 243 | `continuity-proof-v1_1-reconciled-integration.mjs` | `61A4D549F0DD9730` | `TRUNCATED_NOT_COMPLETE` | PASS |  |
| 244 | `continuity-proof-v1_1-reconciled-integration.mjs` | `61A4D549F0DD9730` | `CHECKPOINT_BINDS_FINAL_HEAD` | PASS |  |
| 245 | `continuity-proof-v1_1-reconciled-integration.mjs` | `61A4D549F0DD9730` | `CONTINUITY_COMPLETE_WITH_CLOSED_CHECKPOINT` | PASS |  |
| 246 | `continuity-proof-v1_1-reconciled-integration.mjs` | `61A4D549F0DD9730` | `EXTERNAL_WITNESS_EQUIVOCATION_PROVEN` | PASS |  |
| 247 | `continuity-proof-v1_1-reconciled-integration.mjs` | `61A4D549F0DD9730` | `PRE_COMPROMISE_PROOF_VALID` | PASS |  |
| 248 | `continuity-proof-v1_1-reconciled-integration.mjs` | `61A4D549F0DD9730` | `POST_COMPROMISE_QUARANTINED` | PASS |  |
| 249 | `continuity-proof-v1_1-reconciled-integration.mjs` | `61A4D549F0DD9730` | `NEW_KEY_AFTER_ROTATION_VALID` | PASS |  |
| 250 | `continuity-proof-v1_1-reconciled-integration.mjs` | `61A4D549F0DD9730` | `PARENT_CHAIN_VALID` | PASS |  |
| 251 | `continuity-proof-v1_1-reconciled-integration.mjs` | `61A4D549F0DD9730` | `RECONCILED_INTEGRATION` | PASS |  |

---

## Per-Probe Summary

| Probe | SHA-256 | Checks | PASS | FAIL |
|-------|---------|--------|------|------|
| `PROOF.mjs` | `AAA12410D71AE8989C71CFDAEF4DED6382CC27351F81B0769596CAD31A03740E` | 11 | 11 | 0 |
| `_full-audit.mjs` | `D750218CA313C9430DE08F467A07CEBA0554E5B449BEF4C9FB21A56B5C4008A8` | 33 | 33 | 0 |
| `v1_1-regression-gate.mjs` | `7F768D6C0CD52A69925B1C530126A40ABD0F0B27C7FABC291AB16B63FA7C97CC` | 13 | 13 | 0 |
| `v1_1-integration-probe.mjs` | `7E5D75E73C4FB49F996CD1D5E3941FADCF3229832FACFC607F631C2AA35F7457` | 6 | 6 | 0 |
| `v1_1-chain-probe.mjs` | `13171C3E12FB91DC40FFD7C0DADA7C9695490DD6409D7F5CA54276CA174F2992` | 7 | 7 | 0 |
| `v1_1-scale-chain-probe.mjs` | `C9CA5E0AF62DF0D5D4FF47F1C48E7C09895337B9B1598036CEB62D80BDD0FD65` | 2 | 2 | 0 |
| `v1_1-trusted-chain-probe.mjs` | `AB03B5DDFDBCF02DADAAB7E3A71FC5F16CC4DA6568A338330DA3D48F31314D9A` | 7 | 7 | 0 |
| `v1_1-sequence-guard-probe.mjs` | `8404094B0968236E979ED3DA011D141533F7F076978FCE6BCCB0CB54817CD08C` | 9 | 9 | 0 |
| `v1_1-durable-sequence-probe.mjs` | `62C83E94CDC5121EEB2099A5588145AC50ABDF7809D9BAC77374D1B73BC542E5` | 22 | 22 | 0 |
| `v1_1-witness-probe-v2.mjs` | `CD3082A01778769DB3A93DDEA5D9E5275D6C828097BEFDC100B7FB9621B1E91E` | 13 | 13 | 0 |
| `v1_1-witness-fail-closed-probe.mjs` | `12560BB48D0A7959BAD202BA810080E2B2C1D79F3C646D47D50E05246DF12878` | 10 | 10 | 0 |
| `v1_1-portable-package-probe-v2.mjs` | `C30031CDD6D817970DEF324EA7BE93967CAC38A4E5C418243733F42618774E42` | 9 | 9 | 0 |
| `v1_1-full-integration-probe.mjs` | `1CD85A7F5036AF720FB68AA4613FD615764529D839A5483E57A48942A97BE28C` | 25 | 25 | 0 |
| `v1_1-key-lifecycle-probe.mjs` | `D9A010C51C6F4DE50ED4D02E6B9C874D4CFA3F0A829D0C806881AB7D17D91F38` | 28 | 28 | 0 |
| `v1_1-lifecycle-integration-probe.mjs` | `4A87EEABFCE2D80DA3C07A934A0F6E4F691189C5AEC76CA90D015F3ADBD263D1` | 7 | 7 | 0 |
| `v1_1-oidc-adapter-probe.mjs` | `887A20A45D9876CCA4C934C8AE2C84FD3C1A9FBC41B7DF0BB5C6D4161BBD54F1` | 3 | 3 | 0 |
| `v1_1-witness-atomic-receipt-probe.mjs` | `A104170478C6CEC81F243105C979ACA9A4D03BEBF56145BC6125C5AD57029C5C` | 7 | 7 | 0 |
| `v1_1-witness-crash-boundary-probe.mjs` | `AB9E1C9D39D7EFF87A9C15100DA87869E2D8F0FE8ED4A9F030F123B7D0321528` | 4 | 4 | 0 |
| `continuity-proof-v1_1-p0-critical-gaps.mjs` | `C3D40E7F1A3E2DF6D9CE19D7F64BC7CBA848E223C5C4AE86E1DF1A2185F793FA` | 18 | 18 | 0 |
| `continuity-proof-v1_1-reconciled-integration.mjs` | `61A4D549F0DD973039E2C5A544FBCC4DC9C70BD8A29BD5356C96889B6783486E` | 17 | 17 | 0 |
