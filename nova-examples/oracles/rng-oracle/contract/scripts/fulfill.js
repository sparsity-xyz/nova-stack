const hre = require("hardhat");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

async function main() {
  // Get configuration from environment variables or command line
  const operatorPrivateKey = process.env.OPERATOR_PRIVATE_KEY;
  const requestId = process.env.REQUEST_ID || process.argv[2];

  if (!operatorPrivateKey) {
    console.error("\n❌ Missing operator private key!");
    console.log("\nPlease provide operator private key:");
    console.log("  OPERATOR_PRIVATE_KEY=0x... npx hardhat run scripts/fulfill-random.js --network localhost");
    console.log("\nOr set it in .env file");
    process.exit(1);
  }

  if (!requestId) {
    console.error("\n❌ Missing request ID!");
    console.log("\nUsage:");
    console.log("  REQUEST_ID=1 OPERATOR_PRIVATE_KEY=0x... npx hardhat run scripts/fulfill-random.js --network localhost");
    console.log("\nOr:");
    console.log("  OPERATOR_PRIVATE_KEY=0x... npx hardhat run scripts/fulfill-random.js --network localhost 1");
    process.exit(1);
  }

  console.log("\n" + "=".repeat(70));
  console.log("🎲 Fulfilling Random Number Request");
  console.log("=".repeat(70));

  // Read contract address from deployment.json
  const deploymentPath = path.join(__dirname, "../rng-deployment.json");

  if (!fs.existsSync(deploymentPath)) {
    throw new Error(
      "rng-deployment.json not found!\n" +
      "Please deploy RNG contract first"
    );
  }

  const deployment = JSON.parse(fs.readFileSync(deploymentPath, "utf8"));
  const contractAddress = deployment.contractAddress;

  console.log("\n📋 Configuration:");
  console.log("   Contract:", contractAddress);
  console.log("   Network:", hre.network.name);
  console.log("   Request ID:", requestId);

  // Create wallet using operator private key
  const operator = new hre.ethers.Wallet(operatorPrivateKey, hre.ethers.provider);
  let operatorBalance = await hre.ethers.provider.getBalance(operator.address);

  console.log("\n👤 Operator:");
  console.log("   Address:", operator.address);
  console.log("   Balance:", hre.ethers.formatEther(operatorBalance), "ETH");

  // If balance is low, auto fund
  const minBalance = hre.ethers.parseEther("0.1"); // Minimum required 0.1 ETH
  if (operatorBalance < minBalance) {
    console.log("\n⚠️  Operator balance too low, funding account...");

    // Get first account (usually deployer with lots of ETH)
    const [funder] = await hre.ethers.getSigners();
    const funderBalance = await hre.ethers.provider.getBalance(funder.address);

    console.log("\n💰 Funder:");
    console.log("   Address:", funder.address);
    console.log("   Balance:", hre.ethers.formatEther(funderBalance), "ETH");

    // Transfer 0.1 ETH to operator
    const fundAmount = hre.ethers.parseEther("0.1");

    if (funderBalance < fundAmount) {
      throw new Error(
        "Funder doesn't have enough balance!\n" +
        `Funder balance: ${hre.ethers.formatEther(funderBalance)} ETH\n` +
        `Need: ${hre.ethers.formatEther(fundAmount)} ETH`
      );
    }

    console.log("\n📤 Sending", hre.ethers.formatEther(fundAmount), "ETH to operator...");
    const fundTx = await funder.sendTransaction({
      to: operator.address,
      value: fundAmount
    });

    console.log("   Tx Hash:", fundTx.hash);
    await fundTx.wait();

    // Update balance
    operatorBalance = await hre.ethers.provider.getBalance(operator.address);
    console.log("   ✅ Funded! New balance:", hre.ethers.formatEther(operatorBalance), "ETH");
  }

  // Connect to contract
  const RNG = await hre.ethers.getContractAt("RandomNumberGenerator", contractAddress, operator);

  // Verify operator permission
  const isOperator = await RNG.isOperator(operator.address);
  if (!isOperator) {
    throw new Error(
      `❌ ${operator.address} is not registered as operator!\n` +
      "Please register operator first:\n" +
      `  OPERATOR_ADDRESS=${operator.address} npx hardhat run scripts/register-operator.js --network ${hre.network.name}`
    );
  }
  console.log("   ✅ Operator authorized");

  // Get request info
  console.log("\n🔍 Fetching request info...");
  const request = await RNG.getRequest(requestId);

  console.log("   Requester:", request.requester);
  console.log("   Status:", getStatusName(request.status));
  console.log("   Range: [" + request.min + ", " + request.max + ")");
  console.log("   Count:", request.count.toString());
  console.log("   Callback:", request.callbackContract || "None");

  if (request.status !== 0n) { // 0 = Pending
    console.log("\n⚠️  Request is not pending!");
    console.log("   Current status:", getStatusName(request.status));

    if (request.status === 1n) { // Fulfilled
      console.log("   Random Numbers:", request.randomNumbers.map(n => n.toString()).join(", "));
    }

    return;
  }

  // Generate true random numbers
  console.log("\n🎲 Generating random numbers...");
  const randomNumbers = generateTrueRandomNumbers(
    Number(request.min),
    Number(request.max),
    Number(request.count)
  );

  console.log("   Generated:", randomNumbers.join(", "));

  // Estimate gas
  console.log("\n⛽ Estimating gas...");
  try {
    const gasEstimate = await RNG.fulfillRandomNumber.estimateGas(requestId, randomNumbers);
    console.log("   Estimated Gas:", gasEstimate.toString());
  } catch (error) {
    console.log("   ⚠️  Gas estimation failed:", error.message);
  }

  // Fulfill random numbers
  console.log("\n📤 Sending fulfill transaction...");

  try {
    const tx = await RNG.fulfillRandomNumber(requestId, randomNumbers);
    console.log("   Tx Hash:", tx.hash);

    console.log("\n⏳ Waiting for confirmation...");
    const receipt = await tx.wait();

    console.log("\n✅ Transaction confirmed!");
    console.log("   Block Number:", receipt.blockNumber);
    console.log("   Gas Used:", receipt.gasUsed.toString());
    console.log("   Status:", receipt.status === 1 ? "✅ Success" : "❌ Failed");

    // Check events
    const events = receipt.logs
      .map(log => {
        try {
          return RNG.interface.parseLog(log);
        } catch {
          return null;
        }
      })
      .filter(e => e !== null);

    console.log("\n📊 Events:");
    for (const event of events) {
      console.log("   -", event.name);
      if (event.name === "RandomNumberFulfilled") {
        console.log("     Request ID:", event.args.requestId.toString());
        console.log("     Random Numbers:", event.args.randomNumbers.map(n => n.toString()).join(", "));
      }
      if (event.name === "CallbackExecuted") {
        console.log("     Callback Contract:", event.args.callbackContract);
        console.log("     Success:", event.args.success);
        if (!event.args.success) {
          console.log("     Return Data:", event.args.returnData);
        }
      }
    }

    // Verify result
    console.log("\n🔍 Verifying result...");
    const updatedRequest = await RNG.getRequest(requestId);
    console.log("   Status:", getStatusName(updatedRequest.status));
    console.log("   Random Numbers:", updatedRequest.randomNumbers.map(n => n.toString()).join(", "));
    console.log("   Callback Executed:", updatedRequest.callbackExecuted);

    if (updatedRequest.fulfilledAt > 0) {
      const fulfilledDate = new Date(Number(updatedRequest.fulfilledAt) * 1000);
      console.log("   Fulfilled At:", fulfilledDate.toISOString());
    }

    console.log("\n" + "=".repeat(70));
    console.log("🎉 Random number fulfilled successfully!");
    console.log("=".repeat(70));

  } catch (error) {
    console.error("\n❌ Fulfill failed:");
    console.error(error.message);

    if (error.message.includes("Request not pending")) {
      console.log("\n💡 This request may have already been fulfilled");
    } else if (error.message.includes("Invalid count")) {
      console.log("\n💡 The number of random numbers doesn't match the request");
    } else if (error.message.includes("out of range")) {
      console.log("\n💡 Generated random numbers are outside the valid range");
    } else if (error.message.includes("Not authorized operator")) {
      console.log("\n💡 This address is not registered as an operator");
    }

    throw error;
  }
}

/**
 * Generate true random numbers
 * @param {number} min Minimum value (inclusive)
 * @param {number} max Maximum value (exclusive)
 * @param {number} count Count
 * @returns {number[]} Array of random numbers
 */
function generateTrueRandomNumbers(min, max, count) {
  const randomNumbers = [];
  const range = max - min;

  for (let i = 0; i < count; i++) {
    // Use Node.js crypto module to generate cryptographically secure random numbers
    const randomBytes = crypto.randomBytes(4);
    const randomValue = randomBytes.readUInt32BE(0);
    const randomNumber = min + (randomValue % range);
    randomNumbers.push(randomNumber);
  }

  return randomNumbers;
}

function getStatusName(status) {
  const names = ["Pending", "Fulfilled", "Cancelled"];
  return names[Number(status)] || "Unknown";
}

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error("\n❌ Error:");
    console.error(error);
    process.exit(1);
  });