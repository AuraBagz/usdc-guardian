// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/**
 * @title AgentEscrow
 * @notice Trustless USDC escrow for agent-to-agent commerce on testnet.
 * @dev Part of USDC Guardian — Security-First Agentic Finance.
 * 
 * Flow:
 *   1. Agent A creates an escrow, depositing USDC + describing the task
 *   2. Agent B accepts the escrow and performs the work
 *   3. Agent A releases funds to Agent B upon completion
 *   4. If Agent A doesn't release within the timeout, Agent B can claim
 *   5. Agent A can cancel and reclaim if nobody accepted yet
 *
 * Build: SHA256("AURA-FattyBagz-USDCGuardian-20260207-OpenClaw")
 *      = 047ef8bc6ce9e256c25e1982345039103211b13e72504b62d30524894506d845
 */

interface IERC20 {
    function transferFrom(address from, address to, uint256 amount) external returns (bool);
    function transfer(address to, uint256 amount) external returns (bool);
    function balanceOf(address account) external view returns (uint256);
    function approve(address spender, uint256 amount) external returns (bool);
}

contract AgentEscrow {
    // ── State ────────────────────────────────────────────────────────

    enum Status { Open, Accepted, Released, Cancelled, Claimed }

    struct Escrow {
        address creator;        // Agent A (buyer)
        address worker;         // Agent B (seller) — set on accept
        address token;          // USDC contract address
        uint256 amount;         // USDC amount (6 decimals)
        string taskHash;        // IPFS hash or description hash of the task
        Status status;
        uint256 createdAt;
        uint256 acceptedAt;
        uint256 timeout;        // Seconds after acceptance before worker can auto-claim
    }

    uint256 public escrowCount;
    mapping(uint256 => Escrow) public escrows;

    // Testnet USDC addresses (hardcoded for safety)
    mapping(address => bool) public allowedTokens;
    
    // Events
    event EscrowCreated(uint256 indexed id, address indexed creator, uint256 amount, string taskHash);
    event EscrowAccepted(uint256 indexed id, address indexed worker);
    event EscrowReleased(uint256 indexed id, address indexed worker, uint256 amount);
    event EscrowCancelled(uint256 indexed id, address indexed creator, uint256 amount);
    event EscrowClaimed(uint256 indexed id, address indexed worker, uint256 amount);

    // ── Constructor ──────────────────────────────────────────────────

    constructor(address[] memory _allowedTokens) {
        for (uint256 i = 0; i < _allowedTokens.length; i++) {
            allowedTokens[_allowedTokens[i]] = true;
        }
    }

    // ── Core Functions ───────────────────────────────────────────────

    /**
     * @notice Create an escrow. Caller deposits USDC.
     * @param token USDC contract address (must be in allowedTokens)
     * @param amount USDC amount to escrow (6 decimals)
     * @param taskHash Description or IPFS hash of the task
     * @param timeout Seconds after acceptance before worker can auto-claim (min 1 hour)
     */
    function createEscrow(
        address token,
        uint256 amount,
        string calldata taskHash,
        uint256 timeout
    ) external returns (uint256) {
        require(allowedTokens[token], "Token not allowed");
        require(amount > 0, "Amount must be positive");
        require(amount <= 10000 * 1e6, "Exceeds max escrow (10,000 USDC)");
        require(timeout >= 3600, "Timeout must be >= 1 hour");
        require(bytes(taskHash).length > 0, "Task description required");

        // Transfer USDC from creator to this contract
        require(
            IERC20(token).transferFrom(msg.sender, address(this), amount),
            "USDC transfer failed"
        );

        uint256 id = escrowCount++;
        escrows[id] = Escrow({
            creator: msg.sender,
            worker: address(0),
            token: token,
            amount: amount,
            taskHash: taskHash,
            status: Status.Open,
            createdAt: block.timestamp,
            acceptedAt: 0,
            timeout: timeout
        });

        emit EscrowCreated(id, msg.sender, amount, taskHash);
        return id;
    }

    /**
     * @notice Accept an open escrow. Caller becomes the worker.
     * @param id Escrow ID
     */
    function acceptEscrow(uint256 id) external {
        Escrow storage e = escrows[id];
        require(e.status == Status.Open, "Escrow not open");
        require(msg.sender != e.creator, "Creator cannot accept own escrow");

        e.worker = msg.sender;
        e.status = Status.Accepted;
        e.acceptedAt = block.timestamp;

        emit EscrowAccepted(id, msg.sender);
    }

    /**
     * @notice Release escrowed funds to the worker. Only creator can call.
     * @param id Escrow ID
     */
    function releaseEscrow(uint256 id) external {
        Escrow storage e = escrows[id];
        require(e.status == Status.Accepted, "Escrow not accepted");
        require(msg.sender == e.creator, "Only creator can release");

        e.status = Status.Released;
        require(
            IERC20(e.token).transfer(e.worker, e.amount),
            "USDC transfer failed"
        );

        emit EscrowReleased(id, e.worker, e.amount);
    }

    /**
     * @notice Cancel an escrow and reclaim funds. Only if nobody accepted yet.
     * @param id Escrow ID
     */
    function cancelEscrow(uint256 id) external {
        Escrow storage e = escrows[id];
        require(e.status == Status.Open, "Can only cancel open escrows");
        require(msg.sender == e.creator, "Only creator can cancel");

        e.status = Status.Cancelled;
        require(
            IERC20(e.token).transfer(e.creator, e.amount),
            "USDC refund failed"
        );

        emit EscrowCancelled(id, e.creator, e.amount);
    }

    /**
     * @notice Claim funds after timeout. Only worker can call, only after timeout expires.
     * @param id Escrow ID
     */
    function claimAfterTimeout(uint256 id) external {
        Escrow storage e = escrows[id];
        require(e.status == Status.Accepted, "Escrow not accepted");
        require(msg.sender == e.worker, "Only worker can claim");
        require(
            block.timestamp >= e.acceptedAt + e.timeout,
            "Timeout not reached"
        );

        e.status = Status.Claimed;
        require(
            IERC20(e.token).transfer(e.worker, e.amount),
            "USDC transfer failed"
        );

        emit EscrowClaimed(id, e.worker, e.amount);
    }

    // ── View Functions ───────────────────────────────────────────────

    function getEscrow(uint256 id) external view returns (
        address creator,
        address worker,
        address token,
        uint256 amount,
        string memory taskHash,
        Status status,
        uint256 createdAt,
        uint256 acceptedAt,
        uint256 timeout,
        bool claimable
    ) {
        Escrow storage e = escrows[id];
        bool _claimable = e.status == Status.Accepted && 
                          block.timestamp >= e.acceptedAt + e.timeout;
        return (
            e.creator, e.worker, e.token, e.amount, e.taskHash,
            e.status, e.createdAt, e.acceptedAt, e.timeout, _claimable
        );
    }

    function getOpenEscrows(uint256 offset, uint256 limit) external view returns (uint256[] memory) {
        uint256[] memory temp = new uint256[](limit);
        uint256 count = 0;
        for (uint256 i = offset; i < escrowCount && count < limit; i++) {
            if (escrows[i].status == Status.Open) {
                temp[count++] = i;
            }
        }
        uint256[] memory result = new uint256[](count);
        for (uint256 i = 0; i < count; i++) {
            result[i] = temp[i];
        }
        return result;
    }
}
