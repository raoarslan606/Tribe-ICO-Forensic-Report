#SmartContract_Analysis.md

Tribe ICO — Smart Contract Forensic Analysis
Contract: 0x5d2f721045bc5bc400a0b1dd609dba34741cdb95
Solidity pragma: pragma solidity 0.8.26
Author: Senior Blockchain & Digital Forensics Analyst
Purpose: deep, line-level analysis of the deployed TribeICO contract source provided by client. This file focuses on the on-chain logic, state machine, attack surface, and deterministic failure modes relevant to the ICO non-initiation event.

Executive summary (one-line)

The TribeICO contract implements a typical ERC-20 sale controller gated by an owner-controlled boolean saleStatus. The contract’s sale entry point (buy) is guarded by require(saleStatus, "Sale is not running"). If the owner never executes the activation path (startSale() / updates saleStatus), all buy calls will revert — a deterministic, programmatic block of any token sale. This analysis documents the contract internals, identifies edge cases and weaknesses, and provides concrete recommendations and safe patches.

1 — High-level contract architecture

Primary responsibilities

Accept stablecoin payments (USDT, USDC, FDUSD, BUSD) via buy(uint256 _amount, PaymentType _type).

Calculate token quantity using getCurrentPrice() and calculateToken(...).

Split payment into net funds and tax; forward funds immediately to hardcoded recipients.

Transfer sold tokens (Tribe token) to buyer.

Allow owner to start/stop sale, withdraw raised stablecoins, withdraw unsold tokens, and update parameters.

Key state variables

bool public saleStatus;
mapping(PaymentType => address) public tokenAddresses;
uint256 public usdtPrice;
IERC20 public tokenAddress;      // Tribe token being sold
uint256 public saleCounter;      // price updates counter (unused in getCurrentPrice)
uint256 public soldToken;
address public fundsRecipentAddress;
address public taxRecipentAddress;
uint256 public lastPriceUpdate;
uint256 public PRICE_INCREMENT_INTERVAL = 10 days;
uint256 public PRICE_INCREMENT_PERCENTAGE = 5;
uint256 public Tax_Percentage = 5;
mapping(PaymentType => uint256) private raisedAmounts;
mapping(address => Transaction[]) public userTransactions;


Critical gating condition

require(saleStatus, "Sale is not running");


This single boolean (saleStatus) is the deterministic enable/disable for the entire sale flow.

2 — Function-by-function behavioral analysis (detailed)

Note: functions are presented in logical order for forensic clarity.

constructor
constructor(address _tokenAddress, address _owner, uint256 _usdtPrice) Ownable(_owner) { ... }


Observations / Issues

Calls Ownable(_owner) in the constructor. Standard OpenZeppelin Ownable (v4.x) does not accept an owner address parameter in its constructor — it assigns ownership to msg.sender using _transferOwnership(_msgSender()). Passing _owner as a construction argument will not compile against standard OZ Ownable unless Ownable was modified.
Impact (critical): If the contract was compiled and deployed exactly as shown against standard OZ, it would not compile. If it did deploy, either (a) Ownable was a modified local variant that accepts an owner parameter, or (b) the deployed bytecode differs from this source. This must be reconciled with deployed metadata (compiler & OZ version).

setTokenAddresses() is called to hardcode mainnet stablecoin addresses — acceptable.

Recommendation: Replace Ownable(_owner) with transferOwnership(_owner) inside the constructor body or call _transferOwnership(_owner) after Ownable() default initialization to avoid compilation mismatch.

setTokenAddresses (internal)

Hardcodes Mainnet addresses: USDT, USDC, FDUSD, BUSD.

Fine for fixed acceptance list; be mindful of upgradeability / network differences (testnet vs mainnet).

startSale()
function startSale() external onlyOwner {
    require(!saleStatus, "Sale is already running");
    saleStatus = true;
    lastPriceUpdate = block.timestamp;
    emit SaleStarted();
}


Role: canonical activation function. Owner-only. Sets saleStatus=true and seeds lastPriceUpdate.

Forensics significance: If this function is never called by the owner address, saleStatus remains false and no purchases can proceed. Verifying the absence of startSale() invocation in the contract’s transaction list is irrefutable evidence of non-initiation.

updateSaleStatus(bool _saleStatus)

Owner can toggle saleStatus.

Emits SaleStarted() on true and SaleStopped() on false. (Emits SaleStarted() even if startSale() was intended to be used exclusively — duplication but functional.)

Audit note: Multiple paths to enable sale (startSale or updateSaleStatus(true)). Forensic check must look for both.

buy(uint256 _amount, PaymentType _type)
function buy(uint256 _amount, PaymentType _type) external {
    require(saleStatus, "Sale is not running");
    require(_amount > 0, "Amount must be greater than 0");

    IERC20 paymentToken = IERC20(tokenAddresses[_type]);
    uint256 currentPrice = getCurrentPrice();
    uint256 tokensToReceive = calculateToken(_amount, currentPrice);
    paymentToken.safeTransferFrom(msg.sender, address(this), _amount);
    uint256 taxAmount = _amount.mul(Tax_Percentage).div(100);
    uint256 netAmount = _amount.sub(taxAmount);
    paymentToken.safeTransfer(fundsRecipentAddress, netAmount);
    paymentToken.safeTransfer(taxRecipentAddress, taxAmount);
    raisedAmounts[_type] = raisedAmounts[_type].add(_amount);
    tokenAddress.safeTransfer(msg.sender, tokensToReceive);
    soldToken = soldToken.add(tokensToReceive);
    userTransactions[msg.sender].push(...);
    emit TokenPurchased(msg.sender, _amount, tokensToReceive, currentPrice);
}


Behavioral notes

Uses SafeERC20.safeTransferFrom and safeTransfer for ERC-20 interactions (good practice).

Funds are forwarded directly to recipient addresses rather than kept on contract — reduces centralization of funds in contract but makes on-chain tracking of contributions distributed (you must watch raisedAmounts and recipients).

calculateToken uses tokenAddress.decimals() — potential gas cost retrieving decimals every call but acceptable.

soldToken is incremented after token transfer.

Reentrancy / ordering concerns

The function performs external calls in sequence: safeTransferFrom (payment token), safeTransfer (funds), safeTransfer (tax), then tokenAddress.safeTransfer (transfer sale token to buyer).

Reentrancy risk: Low to medium. The contract does not use ReentrancyGuard. If tokenAddress (the sale token) is ERC-777 or has hooks, safeTransfer may call back into buy() if token is malicious. Similarly, if paymentToken is a malicious ERC-20 (very rare for major stablecoins) or an ERC-777 with hooks, there is potential for reentrancy if state updates occur after external calls. The contract generally updates raisedAmounts before the final token transfer, which mitigates some risk, but soldToken is updated after the token transfer.

Recommendation: Add nonReentrant modifier (OpenZeppelin ReentrancyGuard) and reorder state changes (update internal state before external transfers where safe) or use “checks-effects-interactions” pattern strictly.

getCurrentPrice() (PRICE increment model)
function getCurrentPrice() public view returns (uint256) {
    if (!saleStatus) { return usdtPrice; }
    uint256 timeElapsed = block.timestamp.sub(lastPriceUpdate);
    uint256 intervalsPassed = timeElapsed.div(PRICE_INCREMENT_INTERVAL);
    uint256 currentPrice = usdtPrice;
    for (uint256 i = 0; i < intervalsPassed; i++) {
        currentPrice = currentPrice.add(currentPrice.mul(PRICE_INCREMENT_PERCENTAGE).div(100));
    }
    return currentPrice;
}


Critical observations

Time-based, iterative price bump model. For each PRICE_INCREMENT_INTERVAL that passes, price increases by PRICE_INCREMENT_PERCENTAGE cumulatively.

Gas & DOS risk: intervalsPassed could be large if lastPriceUpdate is very old — the for loop is unbounded relative to a user-supplied parameter. Although this is a view function, getCurrentPrice() is called inside buy() (non-view), which will iterate that many times on-chain and increase gas consumption linearly with intervalsPassed. If intervalsPassed is large enough, a buy() call will run out of gas and revert or be prohibitively expensive — effectively causing a denial-of-service on buys after long idle periods.

Numeric growth: using repeated addition could inflate price extremely rapidly (exponential growth); consider overflow (Solidity 0.8 safe math handles overflow but numbers may be unrealistic).

Recommendation

Replace loop with an exponentiation formula or a capped intervalsPassed calculation:

Compute currentPrice = usdtPrice * (1 + p/100) ** intervalsPassed using fixed-point pow or approximate method.

Impose a sensible maxIntervals cap to avoid excessive iterations.

Alternatively, update lastPriceUpdate and usdtPrice at each manual/owner update to avoid computing historical growth in loops.

updatePriceIncrementInterval(uint256 _interval)
PRICE_INCREMENT_INTERVAL = _interval.mul(1 days);


Note: This expects _interval to be input in days (owner must know the semantics). Acceptable but ensure owner call uses small numbers.

withdrawLockFunds(PaymentType _tokenType)

Resets raisedAmounts[_tokenType] = 0 before doing safeTransfer → good practice (state updated before external transfer to mitigate reentrancy).

Emits TokensWithdrawn (oddly named for withdrawing money in stablecoins — naming mismatch).

withdrawUnSoldTokens(address _to)

Transfers the entire token balance to _to (owner-only). There is no pause or time-lock; owner can drain unsold tokens anytime. Not unusual but should be disclosed.

getSaleInfo()

Returns a composite tuple, but converts fundsRecipentAddress/taxRecipentAddress to uint256 via uint256(uint160(...)). This is acceptable for compact cross-chain tooling but surprising for a public API. Also it returns _tokenAddress then _availableToken.

3 — ABI (function signatures & events) — quick reference

Selected function signatures (human-readable)

constructor(address _tokenAddress, address _owner, uint256 _usdtPrice)

function startSale() external onlyOwner

function updateSaleStatus(bool _saleStatus) external onlyOwner

function updatePriceIncrementPercentage(uint256 _percentage) external onlyOwner

function updatePriceIncrementInterval(uint256 _interval) external onlyOwner

function updateTexPrecenatge(uint256 _percentage) external onlyOwner

function updateToken(IERC20 _token) external onlyOwner

function withdrawLockFunds(PaymentType _tokenType) external onlyOwner

function updateFundsRecipentAddress(address _fundsRecipentAddress) external onlyOwner

function UpdatetaxRecipentAddress(address _taxRecipentAddress) external onlyOwner

function updateTokensAddresses(address _tokenAddress, PaymentType _type) external onlyOwner

function buy(uint256 _amount, PaymentType _type) external

function calculateToken(uint256 _amount, uint256 _currentPrice) public view returns (uint256)

function getCurrentPrice() public view returns (uint256)

function raisedAmount(PaymentType _tokenType) public view returns (uint256)

function TokenPrice() public view returns (uint256) // name misleading

function withdrawUnSoldTokens(address _to) external onlyOwner

function getSaleInfo() public view returns (...)

function tokenSold() public view returns (uint256)

function getUserTransactionHistory(address _user) public view returns (Transaction[] memory)

Events

event TokenPurchased(address indexed user, uint256 amountPaid, uint256 tokensReceived, uint256 pricePerToken);

event TokensWithdrawn(address indexed to, address indexed from, uint256 amount, uint256 timestamp);

event PriceUpdated(uint256 newPrice);

event SaleStarted();

event SaleStopped();

For forensic verification: absence/presence of SaleStarted and TokenPurchased events in the on-chain logs provides decisive evidence for sale activation and purchases.

4 — Storage layout & on-chain forensic checkpoints

Storage slots (logical)

saleStatus (bool)

tokenAddresses mapping (PaymentType -> address)

usdtPrice (uint256)

tokenAddress (IERC20)

saleCounter (uint256)

soldToken (uint256)

fundsRecipentAddress (address)

taxRecipentAddress (address)

lastPriceUpdate (uint256)

PRICE_INCREMENT_INTERVAL (uint256)

PRICE_INCREMENT_PERCENTAGE (uint256)

Tax_Percentage (uint256)

raisedAmounts mapping

userTransactions mapping

Forensic checks to run against chain

Confirm saleStatus getter returns false (default) prior and during marketing window.

Search contract event logs for SaleStarted or SaleStopped emitted by owner address — none found = non-initiation.

Search for TokenPurchased event emissions — none found = no on-chain purchases.

Confirm raisedAmounts remain zero for all PaymentType values.

Confirm tokenAddress.balanceOf(contract) (TokenPrice()) shows unsold tokens still present — indicates no distribution via buy.

Confirm withdrawLockFunds calls (owner-only) — presence means funds were taken off-chain or owner withdrew stablecoin inflows; absence suggests no inflow occurred.

5 — Security & robustness review (concise)

Good practices present

Uses SafeERC20 and SafeMath (although SafeMath not necessary in Solidity 0.8 due to built-in overflow checks).

withdrawLockFunds zeros raisedAmounts before transferring funds — mitigates reentrancy risk.

Owner-only modifiers on sensitive functions.

Weaknesses / recommendations

Ownable(_owner) mismatch — verify actual deployment compile metadata; fix by using transferOwnership(_owner) inside constructor or modify Ownable pattern.

No ReentrancyGuard — add nonReentrant to buy and withdrawUnSoldTokens to protect against malicious token hooks.

Unbounded loop in getCurrentPrice() — replace loop with safe pow/capped approach to avoid gas DOS. Example: compute currentPrice = usdtPrice * ( (100 + p) ** intervalsPassed ) / (100 ** intervalsPassed) with fixed-point pow or iterative owner-side updates.

Naming inconsistencies — TokenPrice() returns token balance, updateTexPrecenatge typo — cosmetic but should be corrected for readability and audit clarity.

Hardcoded stablecoin addresses — if contract is redeployed/tested on testnets, update addresses or allow constructor injection to avoid mistakes.

No timelock/multisig for critical changes — owner can update recipients, tax percentage, price increments; recommend multisig or timelock for funds flow parameters.

Gas cost & economic safety — calculateToken() calls tokenAddress.decimals() (external view); consider caching decimals to reduce gas cost.

6 — Deterministic failure mode that explains zero sales

Root cause (code level): saleStatus is initialized to false and is only toggled by startSale() or updateSaleStatus(true) — both owner-restricted. The buy() method begins with:

require(saleStatus, "Sale is not running");


Therefore, until the owner calls startSale() (or uses updateSaleStatus(true)), any attempt to buy will revert immediately with "Sale is not running".

Forensic proof-pattern (recommended on-chain checks)

Query contract storage: saleStatus → if false during marketing window, sale was inactive.

Inspect event logs: search for SaleStarted() / SaleStopped() events within campaign block range → if none, activation never occurred.

Inspect event logs: search for TokenPurchased(...) → if none, there were no successful buys.

Inspect transfers: check raisedAmounts and recipient addresses for stablecoin liquidity flow (safeTransfer calls emit ERC20 Transfer events to recipient addresses) → if none, funds were never moved because buy never executed.

Confirm tokenAddress.balanceOf(contract) equals initial deposit of tokens → tokens never left contract.

If all checks above show no activation, no events, and token balance unchanged, the only plausible explanation per the source is owner non-execution of startSale() (or updateSaleStatus(true)), i.e., contract non-initiation.

7 — Suggested remediation & safe patch snippets
Fix the Ownable constructor issue
constructor(address _tokenAddress, address _owner, uint256 _usdtPrice) {
    tokenAddress = IERC20(_tokenAddress);
    usdtPrice = _usdtPrice;
    setTokenAddresses();
    transferOwnership(_owner); // explicitly transfer ownership to _owner
}

Add ReentrancyGuard and apply to buy
import "@openzeppelin/contracts/security/ReentrancyGuard.sol";

contract TribeICO is Ownable, ReentrancyGuard {
   // ...
   function buy(uint256 _amount, PaymentType _type) external nonReentrant {
       // checks-effects-interactions pattern
       require(saleStatus, "Sale is not running");
       // ... compute tokensToReceive

       // effects before interactions (if possible)
       raisedAmounts[_type] = raisedAmounts[_type].add(_amount);
       soldToken = soldToken.add(tokensToReceive);
       userTransactions[msg.sender].push(...);

       // interactions
       paymentToken.safeTransferFrom(msg.sender, address(this), _amount);
       paymentToken.safeTransfer(fundsRecipentAddress, netAmount);
       paymentToken.safeTransfer(taxRecipentAddress, taxAmount);
       tokenAddress.safeTransfer(msg.sender, tokensToReceive);

       emit TokenPurchased(...);
   }
}

Replace loop with capped exponentiation or capped intervals
uint256 public MAX_INTERVALS = 365; // example cap

function getCurrentPrice() public view returns (uint256) {
    if (!saleStatus) return usdtPrice;
    uint256 timeElapsed = block.timestamp - lastPriceUpdate;
    uint256 intervalsPassed = timeElapsed / PRICE_INCREMENT_INTERVAL;
    if (intervalsPassed == 0) return usdtPrice;
    if (intervalsPassed > MAX_INTERVALS) intervalsPassed = MAX_INTERVALS;
    // Compute price using exponentiation in fixed point or iterative with cap
    uint256 currentPrice = usdtPrice;
    for (uint256 i = 0; i < intervalsPassed; ++i) {
        currentPrice = currentPrice + (currentPrice * PRICE_INCREMENT_PERCENTAGE) / 100;
    }
    return currentPrice;
}


Better: calculate off-chain and only store price updates on chain when owner triggers; or use logarithmic math libraries for pow.

8 — Forensic summary & final statements (technical)

The contract’s sale activation is explicitly owner gated. Activation occurs only via owner calling startSale() or updateSaleStatus(true).

If the owner never invoked activation (no SaleStarted() events, no TokenPurchased() events, saleStatus == false across campaign window), the contract’s require(saleStatus, "...") prevents any purchase — this is deterministic programmatic blocking of sales.

Additional code issues (constructor Ownable signature mismatch, unbounded price loop, missing reentrancy guard) represent operational risks and should be noted in remediation, but they are not needed to explain the zero-sales outcome. The single boolean gate saleStatus suffices to explain 100% of the observed sales absence when it remains unset.

9 — Actionable on-chain forensic checklist (to cite in your Git report)

Run the following checks and capture the outputs (screenshots / tx hashes / JSON) as exhibits:

saleStatus getter value at times T0..Tn (campaign window) — expected false.

Search Etherscan logs for SaleStarted() and SaleStopped() — expected none.

Search Etherscan logs for TokenPurchased(...) — expected none.

Query raisedAmount(PaymentType.USDT) (and others) — expected 0.

Query tokenAddress.balanceOf(contract) — expected > 0 (unsold tokens present).

Verify contract constructor metadata and compiler version — ensure deployed bytecode matches source.

If available: capture buy() revert traces (if any buyer attempted and got Sale is not running) — this is strong evidence (tx revert reason).

Collect the above and include them as appendices in the Git repo (assets/etherscan_proof.png, assets/tx_revert_example.json) for audit-grade evidence.
