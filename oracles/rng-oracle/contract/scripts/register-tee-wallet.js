const hre = require("hardhat");
const fs = require("fs");
const path = require("path");

async function main() {
  // Get TEE wallet address from command line arguments
  const args = process.argv. slice(2);
  const separatorIndex = args.indexOf('--');
  const teeWalletAddress = separatorIndex !== -1 && args[separatorIndex + 1]
    ? args[separatorIndex + 1]
    : process.env.TEE_WALLET_ADDRESS;

  if (!teeWalletAddress) {
    console.error("\n❌ Missing TEE wallet address!");
    console.log("\nUsage:");
    console.log("  npx hardhat run scripts/register-tee-wallet.js --network <network> -- <tee_wallet_address>");
    console.log("\nOr use environment variable:");
    console.log("  TEE_WALLET_ADDRESS=0x...  npx hardhat run scripts/register-tee-wallet.js --network <network>");
    console. log("\nExample:");
    console.log("  npx hardhat run scripts/register-tee-wallet.js --network baseSepolia -- 0x70997970C51812dc3A010C7d01b50e0d17dc79C8");
    process.exit(1);
  }

  // Validate address format
  if (!hre.ethers.isAddress(teeWalletAddress)) {
    throw new Error(`Invalid TEE wallet address: ${teeWalletAddress}`);
  }

  console.log("\n" + "=".repeat(70));
  console.log("🔧 Registering TEE Wallet");
  console.log("=".repeat(70));

  // Read RNG contract address from deployment.json
  const rngDeploymentPath = path. join(__dirname, "../rng-deployment.json");

  if (! fs.existsSync(rngDeploymentPath)) {
    throw new Error(
      "rng-deployment.json not found!\n" +
      "Please deploy RNG contract first:\n" +
      `  npx hardhat run scripts/deploy-rng. js --network ${hre.network.name}`
    );
  }

  const rngDeployment = JSON.parse(fs.readFileSync(rngDeploymentPath, "utf8"));
  const rngContractAddress = rngDeployment.contractAddress;

  // Read Nova Registry address
  const novaRegistryAddress = rngDeployment.novaRegistryAddress;

  if (!novaRegistryAddress || novaRegistryAddress === "Not set") {
    throw new Error(
      "Nova Registry address not set!\n" +
      "Please set Nova Registry first:\n" +
      `  npx hardhat run scripts/set-nova-registry.js --network ${hre.network.name} -- <registry_address>`
    );
  }

  console.log("\n📋 Configuration:");
  console.log("   RNG Contract:", rngContractAddress);
  console.log("   Nova Registry:", novaRegistryAddress);
  console.log("   Network:", rngDeployment.network);
  console.log("   TEE Wallet:", teeWalletAddress);

  // Check network match
  if (rngDeployment.network !== hre.network.name) {
    console. log("\n⚠️  WARNING: Network mismatch!");
    console.log(`   Deployment network: ${rngDeployment.network}`);
    console. log(`   Current network: ${hre.network.name}`);
    console.log("\n   Waiting 3 seconds... (Ctrl+C to cancel)");
    await new Promise(resolve => setTimeout(resolve, 3000));
  }

  const [signer] = await hre.ethers.getSigners();
  console.log("\n👤 Signer:", signer.address);

  // Get contracts
  const RNG = await hre.ethers.getContractAt("RandomNumberGenerator", rngContractAddress);

  // Check if already an operator
  const isOperatorBefore = await RNG.operators(teeWalletAddress);
  console.log("\n🔍 Current status:", isOperatorBefore ? "✅ Already registered" : "❌ Not registered");

  if (isOperatorBefore) {
    console.log("\n✅ TEE Wallet is already registered as operator!");
    console.log("=".repeat(70));
    return;
  }

  // Register TEE wallet through Nova Registry
  console.log("\n📤 Sending transaction to register TEE Wallet...");

  // Call registerTEEWallet
  const tx = await RNG.registerTEEWallet(teeWalletAddress);
  console.log("   Tx Hash:", tx.hash);

  console. log("\n⏳ Waiting for confirmation...");
  const receipt = await tx.wait();

  console.log("\n✅ Transaction confirmed!");
  console. log("   Block Number:", receipt.blockNumber);
  console.log("   Gas Used:", receipt.gasUsed.toString());

  // Verify the registration
  const isOperatorAfter = await RNG.operators(teeWalletAddress);
  console.log("\n🔍 Verification:", isOperatorAfter ? "✅ Is operator" : "❌ Failed");

  // Check for OperatorUpdated event
  const operatorUpdatedEvent = receipt. logs.find(
    log => {
      try {
        const parsed = RNG.interface.parseLog(log);
        return parsed && parsed.name === 'OperatorUpdated';
      } catch {
        return false;
      }
    }
  );

  if (operatorUpdatedEvent) {
    const parsed = RNG.interface.parseLog(operatorUpdatedEvent);
    console.log("\n📢 Event emitted:");
    console. log("   Event: OperatorUpdated");
    console.log("   Operator:", parsed.args[0]);
    console.log("   Status:", parsed.args[1] ? "Enabled ✅" : "Disabled ❌");
  }

  // Save TEE wallet info
  const teeWalletInfo = {
    rngContractAddress: rngContractAddress,
    novaRegistryAddress: novaRegistryAddress,
    teeWalletAddress: teeWalletAddress,
    registeredBy: signer.address,
    registeredAt: new Date().toISOString(),
    network: hre.network.name,
    txHash: tx. hash,
    blockNumber: receipt.blockNumber,
    isOperator: isOperatorAfter
  };
  let operatorBalance = await hre.ethers.provider.getBalance(teeWalletAddress);
  const minBalance = hre.ethers.parseEther("0.1"); // Minimum required 0.1 ETH
  if (operatorBalance < minBalance) {
    console.log("\n⚠️  Operator balance too low, funding account...");

    // Get first account (usually deployer with lots of ETH)
    const [funder] = await hre.ethers.getSigners();
    const funderBalance = await hre.ethers.provider.getBalance(funder.address);

    console.log("\n💰 Funder:");
    console.log("   Address:", funder.address);
    console.log("   Balance:", hre.ethers.formatEther(funderBalance), "ETH");

    // Transfer 1 ETH to operator
    const fundAmount = hre.ethers.parseEther("1");

    if (funderBalance < fundAmount) {
      throw new Error(
        "Funder doesn't have enough balance!\n" +
        `Funder balance: ${hre.ethers.formatEther(funderBalance)} ETH\n` +
        `Need: ${hre.ethers.formatEther(fundAmount)} ETH`
      );
    }

    console.log("\n📤 Sending", hre.ethers.formatEther(fundAmount), "ETH to operator...");
    const fundTx = await funder.sendTransaction({
      to: teeWalletAddress,
      value: fundAmount
    });

    console.log("   Tx Hash:", fundTx.hash);
    await fundTx.wait();

    // Update balance
    operatorBalance = await hre.ethers.provider.getBalance(teeWalletAddress);
    console.log("   ✅ Funded! New balance:", hre.ethers.formatEther(operatorBalance), "ETH");
  }

  // Load or create TEE wallets list
  const teeWalletsPath = path. join(__dirname, "../tee-wallets.json");
  let teeWalletsList = { wallets: [] };

  if (fs.existsSync(teeWalletsPath)) {
    teeWalletsList = JSON. parse(fs.readFileSync(teeWalletsPath, "utf8"));
  }

  // Add new wallet to list (avoid duplicates)
  const existingIndex = teeWalletsList. wallets.findIndex(
    w => w.teeWalletAddress. toLowerCase() === teeWalletAddress.toLowerCase()
  );

  if (existingIndex >= 0) {
    teeWalletsList.wallets[existingIndex] = teeWalletInfo;
  } else {
    teeWalletsList.wallets.push(teeWalletInfo);
  }

  fs.writeFileSync(teeWalletsPath, JSON.stringify(teeWalletsList, null, 2));
  console. log("\n💾 TEE wallet info saved to tee-wallets. json");

  // Summary
  console.log("\n📊 Summary:");
  console. log("   Total TEE Wallets registered:", teeWalletsList. wallets.length);

  console.log("\n" + "=".repeat(70));
  console.log("🎉 TEE Wallet registered successfully!");
  console.log("=".repeat(70));
}

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console. error("\n❌ Error:");
    console.error(error. message);
    if (error. stack) {
      console.error("\nStack trace:");
      console.error(error.stack);
    }
    process.exit(1);
  });