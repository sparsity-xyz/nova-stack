const hre = require("hardhat");
const fs = require("fs");
const path = require("path");

async function main() {
  // Get operator address from command line arguments
  const args = process.argv.slice(2);
  const separatorIndex = args.indexOf('--');
  const operatorAddress = separatorIndex !== -1 && args[separatorIndex + 1]
    ? args[separatorIndex + 1]
    : process.env.OPERATOR_ADDRESS;

  if (!operatorAddress) {
    console.error("\n❌ Missing operator address!");
    console.log("\nUsage:");
    console.log("  npx hardhat run scripts/register-operator.js --network <network> -- <operator_address>");
    console.log("\nOr use environment variable:");
    console.log("  OPERATOR_ADDRESS=0x... npx hardhat run scripts/register-operator.js --network <network>");
    console.log("\nExample:");
    console.log("  npx hardhat run scripts/register-operator.js --network baseSepolia -- 0x70997970C51812dc3A010C7d01b50e0d17dc79C8");
    process.exit(1);
  }

  // Validate address format
  if (!hre.ethers.isAddress(operatorAddress)) {
    throw new Error(`Invalid operator address: ${operatorAddress}`);
  }

  console.log("\n" + "=".repeat(70));
  console.log("🔧 Registering RNG Operator");
  console.log("=".repeat(70));

  // Read contract address from deployment.json
  const deploymentPath = path.join(__dirname, "../rng-deployment.json");

  if (!fs.existsSync(deploymentPath)) {
    throw new Error(
      "rng-deployment.json not found!\n" +
      "Please deploy RNG contract first:\n" +
      `  npx hardhat run scripts/deploy-rng.js --network ${hre.network.name}`
    );
  }

  const deployment = JSON.parse(fs.readFileSync(deploymentPath, "utf8"));
  const contractAddress = deployment.contractAddress;

  console.log("\n📋 Configuration:");
  console.log("   Contract:", contractAddress);
  console.log("   Network:", deployment.network);
  console.log("   Operator:", operatorAddress);

  // Check network match
  if (deployment.network !== hre.network.name) {
    console.log("\n⚠️  WARNING: Network mismatch!");
    console.log(`   Deployment network: ${deployment.network}`);
    console.log(`   Current network: ${hre.network.name}`);
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

  // Check if already operator
  const isOperatorBefore = await RNG.isOperator(operatorAddress);
  console.log("\n🔍 Current status:", isOperatorBefore ? "✅ Already operator" : "❌ Not operator");

  if (isOperatorBefore) {
    console.log("\n✅ Address is already registered as operator!");
    console.log("=".repeat(70));
    return;
  }

  // Register operator
  console.log("\n📤 Sending transaction to add operator...");
  const tx = await RNG.addOperator(operatorAddress);
  console.log("   Tx Hash:", tx.hash);

  console.log("\n⏳ Waiting for confirmation...");
  const receipt = await tx.wait();

  console.log("\n✅ Transaction confirmed!");
  console.log("   Block Number:", receipt.blockNumber);
  console.log("   Gas Used:", receipt.gasUsed.toString());

  // Verify
  const isOperatorAfter = await RNG.isOperator(operatorAddress);
  console.log("\n🔍 Verification:", isOperatorAfter ? "✅ Is operator" : "❌ Failed");

  // Save operator info
  const operatorInfo = {
    contractAddress: contractAddress,
    operatorAddress: operatorAddress,
    registeredBy: owner.address,
    registeredAt: new Date().toISOString(),
    network: hre.network.name,
    txHash: tx.hash,
    blockNumber: receipt.blockNumber
  };

  const operatorInfoPath = path.join(__dirname, "../operator-info.json");
  fs.writeFileSync(operatorInfoPath, JSON.stringify(operatorInfo, null, 2));
  console.log("\n💾 Operator info saved to operator-info.json");

  console.log("\n" + "=".repeat(70));
  console.log("🎉 Operator registered successfully!");
  console.log("=".repeat(70));
}

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error("\n❌ Error:");
    console.error(error.message);
    process.exit(1);
  });