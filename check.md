

## 2. Validation Format Function

```python

```

---

## Key Differences from Ekubo Template:

### Protocol-Specific Context:
- **Architecture**: Dual-layer (Settlement + Investment) vs Ekubo's singleton AMM
- **Technology**: ERC-7575/7540 async vaults vs concentrated liquidity DEX
- **Scope**: 6 files (1,670 nSLOC) vs Ekubo's 92 files (6,283 nSLOC)
- **Test exclusion**: Explicitly excludes test/** directory

### Critical Invariants:
- Token supply conservation, zero-sum settlement, dual authorization
- Async state flow (Pending → Claimable → Claimed)
- Reserved asset protection, decimal conversion accuracy
- Role-based access control boundaries

### Attack Vectors:
- **Batch netting abuse** (zero-sum validation)
- **Unit mixing exploits** (shares vs assets in reserved calculation)
- **rBalance manipulation** (investment tracking system)
- **Permit bypass** (dual-allowance requirement)
- **Async state skipping** (ERC-7540 flow integrity)
- **Decimal conversion exploits** (6 vs 18 decimal handling)

### Validation Rules:
- **10 specialized rules** for SukukFi-specific patterns
- Deep focus on reserved asset calculation (potential unit mixing bug)
- Batch transfer netting validation (zero-sum invariant)
- Request cancellation boundaries (pending vs claimable)
- rBalance vs _balances dual-tracking system

### Trust Model:
- **5 trusted roles**: Owner, Validator, KYC Admin, Revenue Admin, Investment Manager
- All admin roles act honestly (extensive KNOWN_ISSUES.md documentation)
- Focus on **unprivileged attacker** exploits only

The validation function is **extremely strict** and will reject:
- Centralization complaints (QA/Low per KNOWN_ISSUES.md)
- Non-standard ERC-20 behavior (intentional design)
- External compatibility issues (not supported)
- Admin mistake scenarios (admins preview actions)
- Theoretical issues without concrete exploit paths

Both functions emphasize **one high-quality finding** with runnable PoCs, not multiple weak claims. 