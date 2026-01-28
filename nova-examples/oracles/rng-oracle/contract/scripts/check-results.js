const hre = require("hardhat");
const fs = require("fs");
const path = require("path");

async function main() {
  const deploymentPath = path.join(__dirname, "../rng-deployment.json");
  const deployment = JSON.parse(fs.readFileSync(deploymentPath, "utf8"));
  const contractAddress = deployment.contractAddress;

  console.log("\n🔍 Checking RNG Results");
  console.log("Contract:", contractAddress);
  console.log("Network:", hre.network.name);

  const [user] = await hre.ethers.getSigners();
  const RNG = await hre.ethers.getContractAt("RandomNumberGenerator", contractAddress);

  const userRequests = await RNG.getUserRequests(user.address);

  console.log("\n📊 Found", userRequests.length, "requests\n");

  for (let i = 0; i < userRequests.length; i++) {
    const requestId = userRequests[i];
    const req = await RNG.getRequest(requestId);
    console.log("Request #" + requestId.toString());
    console.log("  Status:", getStatusName(req.status));
    console.log("  Requester:", req.requester);
    console.log("  Count:", req.count);
    console.log("  Callback:", req.callbackExecuted);
    console.log("  Requested:", new Date(Number(req.timestamp) * 1000).toISOString());

    if (req.status === 1n) { // Fulfilled
      console.log("  Random Numbers:", req.randomNumbers.map(n => n.toString()).join(", "));
      console.log("  Fulfilled:", new Date(Number(req.fulfilledAt) * 1000).toISOString());
      console.log("  ✅ Completed");
    } else if (req.status === 0n) { // Pending
      console.log("  ⏳ Waiting for fulfillment...");
    } else if (req.status === 2n) { // Cancelled
      console.log("  ❌ Cancelled");
    }
    console.log();
  }
}

function getStatusName(status) {
  const names = ["Pending", "Fulfilled", "Cancelled"];
  return names[Number(status)] || "Unknown";
}

main().catch(console.error);