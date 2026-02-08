#!/usr/bin/env node
/**
 * Deploy AgentEscrow to Sepolia Testnet
 * 
 * Usage:
 *   node deploy.js --generate-wallet     Generate a new wallet
 *   node deploy.js --compile             Compile the contract
 *   node deploy.js --deploy              Deploy to Sepolia
 *   node deploy.js --verify              Verify deployment
 */

const { ethers } = require('ethers');
const solc = require('solc');
const fs = require('fs');
const path = require('path');

const SEPOLIA_RPC = 'https://ethereum-sepolia-rpc.publicnode.com';
const SEPOLIA_USDC = '0x1c7D4B196Cb0C7B01d743Fbc6116a902379C7238';
const WALLET_PATH = path.join(__dirname, '.testnet-wallet.json');
const ARTIFACT_PATH = path.join(__dirname, 'contracts', 'AgentEscrow.json');

async function generateWallet() {
  const wallet = ethers.Wallet.createRandom();
  const data = {
    address: wallet.address,
    privateKey: wallet.privateKey,
    mnemonic: wallet.mnemonic.phrase,
    network: 'sepolia',
    created: new Date().toISOString(),
    WARNING: 'TESTNET ONLY. Never use this wallet on mainnet.',
  };
  fs.writeFileSync(WALLET_PATH, JSON.stringify(data, null, 2));
  console.log('\nTestnet Wallet Generated');
  console.log('Address:', wallet.address);
  console.log('Saved to:', WALLET_PATH);
  console.log('\nGet Sepolia ETH from:');
  console.log('  https://www.alchemy.com/faucets/ethereum-sepolia');
  console.log('  https://sepoliafaucet.com');
  console.log('  https://faucet.quicknode.com/ethereum/sepolia');
  return wallet;
}

function compile() {
  const source = fs.readFileSync(path.join(__dirname, 'contracts', 'AgentEscrow.sol'), 'utf-8');
  
  const input = {
    language: 'Solidity',
    sources: {
      'AgentEscrow.sol': { content: source },
    },
    settings: {
      optimizer: { enabled: true, runs: 200 },
      outputSelection: {
        '*': {
          '*': ['abi', 'evm.bytecode.object'],
        },
      },
    },
  };

  const output = JSON.parse(solc.compile(JSON.stringify(input)));
  
  if (output.errors) {
    const errors = output.errors.filter(e => e.severity === 'error');
    if (errors.length > 0) {
      console.error('Compilation errors:');
      errors.forEach(e => console.error(e.formattedMessage));
      process.exit(1);
    }
    // Show warnings
    output.errors.filter(e => e.severity === 'warning').forEach(w => 
      console.warn('Warning:', w.message)
    );
  }

  const contract = output.contracts['AgentEscrow.sol']['AgentEscrow'];
  const artifact = {
    abi: contract.abi,
    bytecode: '0x' + contract.evm.bytecode.object,
    compiler: 'solc-0.8.28',
    optimized: true,
    runs: 200,
  };

  fs.writeFileSync(ARTIFACT_PATH, JSON.stringify(artifact, null, 2));
  console.log('Compiled successfully');
  console.log('ABI:', artifact.abi.length, 'functions');
  console.log('Bytecode:', artifact.bytecode.length, 'chars');
  console.log('Saved to:', ARTIFACT_PATH);
  return artifact;
}

async function deploy() {
  // Load wallet
  let walletData;
  try {
    walletData = JSON.parse(fs.readFileSync(WALLET_PATH, 'utf-8'));
  } catch {
    console.error('No wallet found. Run: node deploy.js --generate-wallet');
    process.exit(1);
  }

  // Load artifact
  let artifact;
  try {
    artifact = JSON.parse(fs.readFileSync(ARTIFACT_PATH, 'utf-8'));
  } catch {
    console.log('Compiling first...');
    artifact = compile();
  }

  const provider = new ethers.JsonRpcProvider(SEPOLIA_RPC);
  const wallet = new ethers.Wallet(walletData.privateKey, provider);
  
  // Check balance
  const balance = await provider.getBalance(wallet.address);
  const ethBalance = ethers.formatEther(balance);
  console.log(`Wallet: ${wallet.address}`);
  console.log(`Balance: ${ethBalance} ETH`);
  
  if (balance === 0n) {
    console.error('\nNo ETH! Get Sepolia ETH from a faucet first.');
    console.log('Address to fund:', wallet.address);
    process.exit(1);
  }

  // Deploy
  console.log('\nDeploying AgentEscrow...');
  const factory = new ethers.ContractFactory(artifact.abi, artifact.bytecode, wallet);
  
  // Constructor takes an array of allowed USDC token addresses
  const allowedTokens = [SEPOLIA_USDC];
  
  const contract = await factory.deploy(allowedTokens, {
    gasLimit: 3000000,
  });

  console.log('Transaction:', contract.deploymentTransaction().hash);
  console.log('Waiting for confirmation...');
  
  await contract.waitForDeployment();
  const address = await contract.getAddress();
  
  console.log('\n✅ AgentEscrow deployed!');
  console.log('Contract:', address);
  console.log('Network: Sepolia (11155111)');
  console.log('Etherscan: https://sepolia.etherscan.io/address/' + address);

  // Save deployment info
  const deployInfo = {
    contract: address,
    deployer: wallet.address,
    network: 'sepolia',
    chainId: 11155111,
    txHash: contract.deploymentTransaction().hash,
    allowedTokens,
    deployedAt: new Date().toISOString(),
    etherscan: 'https://sepolia.etherscan.io/address/' + address,
  };
  fs.writeFileSync(path.join(__dirname, 'contracts', 'deployment.json'), JSON.stringify(deployInfo, null, 2));
  return deployInfo;
}

async function verify() {
  let deployInfo;
  try {
    deployInfo = JSON.parse(fs.readFileSync(path.join(__dirname, 'contracts', 'deployment.json'), 'utf-8'));
  } catch {
    console.error('No deployment found. Run: node deploy.js --deploy');
    process.exit(1);
  }

  const provider = new ethers.JsonRpcProvider(SEPOLIA_RPC);
  const code = await provider.getCode(deployInfo.contract);
  
  console.log('Contract:', deployInfo.contract);
  console.log('Network:', deployInfo.network);
  console.log('Has code:', code.length > 2 ? 'YES (' + code.length + ' bytes)' : 'NO');
  console.log('Etherscan:', deployInfo.etherscan);
  console.log('Deployed:', deployInfo.deployedAt);
}

async function main() {
  const args = process.argv.slice(2);

  if (args.includes('--generate-wallet')) {
    await generateWallet();
  } else if (args.includes('--compile')) {
    compile();
  } else if (args.includes('--deploy')) {
    await deploy();
  } else if (args.includes('--verify')) {
    await verify();
  } else {
    console.log('Usage:');
    console.log('  node deploy.js --generate-wallet');
    console.log('  node deploy.js --compile');
    console.log('  node deploy.js --deploy');
    console.log('  node deploy.js --verify');
  }
}

main().catch(e => { console.error('Error:', e.message); process.exit(1); });
