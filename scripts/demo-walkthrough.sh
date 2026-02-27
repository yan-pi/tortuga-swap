#!/bin/bash
set -euo pipefail

export LIBRARY_PATH="/opt/homebrew/lib:${LIBRARY_PATH:-}"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

print_header() {
    echo -e "${CYAN}============================================================${NC}"
    echo -e "${CYAN}$1${NC}"
    echo -e "${CYAN}============================================================${NC}"
    echo ""
}

print_info() {
    echo -e "${YELLOW}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[OK]${NC} $1"
}

print_warning() {
    echo -e "${RED}[WARNING]${NC} $1"
}

wait_for_enter() {
    echo ""
    echo -e "${YELLOW}Press Enter to continue...${NC}"
    read -r
    echo ""
}

# =============================================================================
# INTRODUCTION
# =============================================================================

print_header "TORTUGA: Anonymous Atomic Swaps with Adaptor Signatures"

echo "Welcome to the Tortuga demo!"
echo ""
echo "Tortuga implements A2L (Anonymous Atomic Locks) - a protocol for"
echo "performing atomic swaps between Bitcoin chains WITHOUT the privacy"
echo "leak present in traditional HTLC-based swaps."
echo ""
echo "In this demo, we will:"
echo "  1. Run a traditional HTLC swap and observe the linkability problem"
echo "  2. Run an A2L swap and see how adaptor signatures solve it"
echo "  3. Compare both approaches side-by-side"
echo ""
print_info "All transactions will be broadcast to a local Bitcoin regtest via Nigiri."

wait_for_enter

# =============================================================================
# CHECK NIGIRI
# =============================================================================

print_header "Pre-flight Check: Verifying Nigiri"

print_info "Checking if Nigiri (local Bitcoin regtest) is running..."

if curl -s http://localhost:3000/blocks/tip/height > /dev/null 2>&1; then
    BLOCK_HEIGHT=$(curl -s http://localhost:3000/blocks/tip/height)
    print_success "Nigiri is running. Current block height: $BLOCK_HEIGHT"
else
    print_warning "Nigiri is not running!"
    echo ""
    echo "Please start Nigiri first:"
    echo "  ./scripts/setup-nigiri.sh"
    echo ""
    exit 1
fi

wait_for_enter

# =============================================================================
# PHASE 1: HTLC SWAP
# =============================================================================

print_header "PHASE 1: Traditional HTLC Swap"

echo "Hash Time-Locked Contracts (HTLCs) are the standard way to perform"
echo "atomic swaps. Here is how they work:"
echo ""
echo "  1. Alice generates a secret 's' and computes H = SHA256(s)"
echo "  2. Alice locks coins on Chain A with: 'Bob can spend if he knows s'"
echo "  3. Bob locks coins on Chain B with: 'Alice can spend if she knows s'"
echo "  4. Alice reveals 's' to claim Bob's coins"
echo "  5. Bob uses the revealed 's' to claim Alice's coins"
echo ""
print_warning "THE PROBLEM: The same hash H appears on BOTH chains!"
echo "  Any observer can trivially link the two legs of the swap."
echo ""

print_info "Running HTLC swap with on-chain transactions..."
echo ""

cargo run --bin tortuga -- htlc-swap --on-chain

echo ""
print_success "HTLC swap completed."
echo ""
print_warning "Privacy Analysis:"
echo "  - The SAME hash lock appeared on both chains"
echo "  - Anyone watching both chains can see: 'These two transactions are linked'"
echo "  - This completely breaks swap privacy"

wait_for_enter

# =============================================================================
# PHASE 2: A2L SWAP
# =============================================================================

print_header "PHASE 2: A2L Swap (Anonymous Atomic Locks)"

echo "A2L uses adaptor signatures instead of hash locks. The key insight:"
echo ""
echo "  Instead of: 'reveal a hash preimage to unlock'"
echo "  We use:     'reveal a discrete log to complete a signature'"
echo ""
echo "How A2L works:"
echo ""
echo "  1. Alice and Bob set up a 2-of-2 multisig on each chain"
echo "  2. Alice creates an adaptor signature with a secret scalar 't'"
echo "  3. The adaptor point T = t*G is used, but NOT revealed directly"
echo "  4. When Alice broadcasts her completed signature, Bob can extract 't'"
echo "  5. Bob uses 't' to complete his own adaptor signature"
echo ""
print_success "THE SOLUTION: Each chain sees a DIFFERENT adaptor point!"
echo "  T1 on Chain A and T2 on Chain B are unlinkable without the secrets."
echo ""

print_info "Running A2L swap with on-chain transactions..."
echo ""

cargo run --bin tortuga -- a2l-swap --on-chain

echo ""
print_success "A2L swap completed."
echo ""
print_success "Privacy Analysis:"
echo "  - Different adaptor points were used on each chain"
echo "  - An observer sees two UNRELATED 2-of-2 multisig spends"
echo "  - No on-chain link between the swap legs"

wait_for_enter

# =============================================================================
# PHASE 3: COMPARISON
# =============================================================================

print_header "PHASE 3: HTLC vs A2L Comparison"

echo "+-----------------------+---------------------------+---------------------------+"
echo "| Property              | HTLC                      | A2L                       |"
echo "+-----------------------+---------------------------+---------------------------+"
echo "| Locking Mechanism     | Hash preimage             | Adaptor signature         |"
echo "| On-chain Fingerprint  | OP_HASH160 script         | Standard 2-of-2 multisig  |"
echo "| Cross-chain Link      | SAME hash on both chains  | DIFFERENT points          |"
echo "| Privacy               | Trivially linkable        | Unlinkable to observers   |"
echo "| Script Complexity     | Custom script             | Taproot keyspend          |"
echo "+-----------------------+---------------------------+---------------------------+"
echo ""

print_success "Key Takeaway:"
echo "  A2L swaps look like ordinary multisig transactions."
echo "  There is no on-chain evidence that a swap even occurred."
echo ""

print_info "Esplora Block Explorer: http://localhost:5005"
echo "  You can inspect the transactions we just created."
echo ""

print_header "Demo Complete"

echo "Tortuga demonstrates that privacy-preserving atomic swaps are possible"
echo "using adaptor signatures. This is crucial for:"
echo ""
echo "  - Cross-chain DEXs that respect user privacy"
echo "  - Lightning Network channel opens/closes"
echo "  - Any application requiring trustless exchange"
echo ""
echo "Learn more:"
echo "  - A2L Paper: https://eprint.iacr.org/2019/589"
echo "  - Adaptor Signatures: https://github.com/discreetlogcontracts/dlcspecs"
echo ""
print_success "Thank you for watching!"
