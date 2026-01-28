const hre = require("hardhat");
const fs = require("fs");
const path = require("path");

async function main() {
  // Get registry address from command line arguments
  const args = process.argv.slice(2);
  const separatorIndex = args.indexOf('--');
  const registryAddress = separatorIndex !== -1 && args[separatorIndex + 1]
    ? args[separatorIndex + 1]
    : process. env.REGISTRY_ADDRESS;

  if (!registryAddress) {
    console.error("\n❌ Missing registry address!");
    console.log("\nUsage:");
    console.log("  npx hardhat run scripts/set-nova-registry.js --network <network> -- <registry_address>");
    console.log("\nOr use environment variable:");
    console.log("  REGISTRY_ADDRESS=0x... npx hardhat run scripts/set-nova-registry.js --network <network>");
    console.log("\nExample:");
    console.log("  npx hardhat run scripts/set-nova-registry.js --network baseSepolia -- 0x70997970C51812dc3A010C7d01b50e0d17dc79C8");
    process.exit(1);
  }

  // Validate address format
  if (!hre.ethers.isAddress(registryAddress)) {
    throw new Error(`Invalid registry address: ${registryAddress}`);
  }

  console.log("\n" + "=".repeat(70));
  console.log("🔧 Setting Nova Registry Address");
  console.log("=".repeat(70));

  // Read contract address from deployment.json
  const deploymentPath = path. join(__dirname, "../rng-deployment.json");

  if (! fs.existsSync(deploymentPath)) {
    throw new Error(
      "rng-deployment.json not found!\n" +
      "Please deploy RNG contract first:\n" +
      `  npx hardhat run scripts/deploy-rng.js --network ${hre.network.name}`
    );
  }

  const deployment = JSON.parse(fs.readFileSync(deploymentPath, "utf8"));
  const contractAddress = deployment.contractAddress;

  console.log("\n📋 Configuration:");
  console. log("   Contract:", contractAddress);
  console.log("   Network:", deployment.network);
  console.log("   New Registry:", registryAddress);

  // Check network match
  if (deployment.network !== hre.network.name) {
    console. log("\n⚠️  WARNING: Network mismatch!");
    console.log(`   Deployment network: ${deployment.network}`);
    console.log(`   Current network: ${hre.network. name}`);
    console.log("\n   Waiting 3 seconds... (Ctrl+C to cancel)");
    await new Promise(resolve => setTimeout(resolve, 3000));
  }

  const [owner] = await hre.ethers.getSigners();
  console.log("\n👤 Owner:", owner.address);

  const RNG = await hre.ethers.getContractAt("RandomNumberGenerator", contractAddress);

  // Verify permission
  const contractOwner = await RNG.owner();
  if (contractOwner.toLowerCase() !== owner.address.toLowerCase()) {
    throw new Error(
      `❌ Signer is not the contract owner!\n` +
      `   Contract Owner: ${contractOwner}\n` +
      `   Your Signer:    ${owner.address}`
    );
  }

  // Check current registry address
  try {
    const currentRegistry = await RNG.novaRegistryAddress();
    console.log("\n🔍 Current registry address:", currentRegistry);

    if (currentRegistry. toLowerCase() === registryAddress.toLowerCase()) {
      console.log("\n✅ Registry address is already set to this value!");
      console.log("=".repeat(70));
      return;
    }
  } catch (error) {
    console. log("\n⚠️  Could not read current registry address (may not be set yet)");
  }

  // Set nova registry
  console.log("\n📤 Sending transaction to set Nova Registry...");
  const tx = await RNG.setNovaRegistry(registryAddress);
  console.log("   Tx Hash:", tx.hash);

  console. log("\n⏳ Waiting for confirmation...");
  const receipt = await tx.wait();

  console.log("\n✅ Transaction confirmed!");
  console. log("   Block Number:", receipt. blockNumber);
  console.log("   Gas Used:", receipt.gasUsed.toString());

  // Verify the change
  const newRegistry = await RNG.novaRegistryAddress();
  const isSuccess = newRegistry.toLowerCase() === registryAddress.toLowerCase();
  console.log("\n🔍 Verification:", isSuccess ? "✅ Registry updated" : "❌ Failed");
  console.log("   New Registry:", newRegistry);

  // Check for SetNovaRegistry event
  const setNovaRegistryEvent = receipt.logs.find(
    log => {
      try {
        const parsed = RNG.interface.parseLog(log);
        return parsed && parsed.name === 'SetNovaRegistry';
      } catch {
        return false;
      }
    }
  );

  if (setNovaRegistryEvent) {
    const parsed = RNG.interface.parseLog(setNovaRegistryEvent);
    console.log("\n📢 Event emitted:");
    console.log("   Event: SetNovaRegistry");
    console.log("   Registry Address:", parsed.args[0]);
  }

  // Save registry info
  const registryInfo = {
    contractAddress: contractAddress,
    novaRegistryAddress: registryAddress,
    previousRegistry: deployment.novaRegistryAddress || "Not set",
    updatedBy: owner.address,
    updatedAt: new Date(). toISOString(),
    network: hre.network.name,
    txHash: tx.hash,
    blockNumber: receipt. blockNumber
  };

  const registryInfoPath = path.join(__dirname, "../nova-registry-info.json");
  fs.writeFileSync(registryInfoPath, JSON.stringify(registryInfo, null, 2));
  console.log("\n💾 Registry info saved to nova-registry-info.json");

  // Update deployment. json with new registry address
  deployment.novaRegistryAddress = registryAddress;
  deployment.lastUpdated = new Date().toISOString();
  fs.writeFileSync(deploymentPath, JSON.stringify(deployment, null, 2));
  console.log("💾 Updated rng-deployment.json with new registry address");

  console.log("\n" + "=".repeat(70));
  console.log("🎉 Nova Registry address set successfully!");
  console.log("=".repeat(70));
}

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error("\n❌ Error:");
    console.error(error.message);
    if (error.stack) {
      console.error("\nStack trace:");
      console.error(error.stack);
    }
    process.exit(1);
  });