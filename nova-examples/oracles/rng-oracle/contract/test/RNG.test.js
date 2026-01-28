const hre = require("hardhat");
const fs = require("fs");
const path = require("path");

async function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

async function main() {
  console.log("\n" + "=".repeat(70));
  console.log("🧪 Testing Random Number Generator");
  console.log("=".repeat(70));

  // Read deployment info
  const deploymentPath = path.join(__dirname, "../rng-deployment.json");

  if (!fs.existsSync(deploymentPath)) {
    console.error("❌ rng-deployment.json not found!");
    console.log("Please deploy first:");
    console.log(`  npx hardhat run scripts/deploy-rng.js --network ${hre.network.name}`);
    process.exit(1);
  }

  const deployment = JSON.parse(fs.readFileSync(deploymentPath, "utf8"));
  const contractAddress = deployment.contractAddress;

  console.log("\n📋 Configuration:");
  console.log("   Contract:", contractAddress);
  console.log("   Network:", hre.network.name);

  const [user] = await hre.ethers.getSigners();
  console.log("   User:", user.address);

  const RNG = await hre.ethers.getContractAt("RandomNumberGenerator", contractAddress);

  // Test 1: Request single random number
  console.log("\n" + "=".repeat(70));
  console.log("🎲 Test 1: Request Random Number (0-100)");
  console.log("=".repeat(70));

  const tx1 = await RNG.requestRandom(100);
  const receipt1 = await tx1.wait();

  console.log("✅ Transaction:", receipt1.hash);

  // Get requestId from event
  const event1 = receipt1.logs.find(log => {
    try {
      const parsed = RNG.interface.parseLog(log);
      return parsed && parsed.name === "RandomNumberRequested";
    } catch { return false; }
  });

  let requestId1;
  if (event1) {
    const parsed = RNG.interface.parseLog(event1);
    requestId1 = parsed.args.requestId;
    console.log("📝 Request ID:", requestId1.toString());
    console.log("   Min:", parsed.args.min.toString());
    console.log("   Max:", parsed.args.max.toString());
    console.log("   Count:", parsed.args.count.toString());
  }

  // Test 2: Request range random numbers
  console.log("\n" + "=".repeat(70));
  console.log("🎲 Test 2: Request Random Range (10-50, count=3)");
  console.log("=".repeat(70));

  const tx2 = await RNG.requestRandomRange(10, 50, 3);
  const receipt2 = await tx2.wait();

  console.log("✅ Transaction:", receipt2.hash);

  const event2 = receipt2.logs.find(log => {
    try {
      const parsed = RNG.interface.parseLog(log);
      return parsed && parsed.name === "RandomNumberRequested";
    } catch { return false; }
  });

  let requestId2;
  if (event2) {
    const parsed = RNG.interface.parseLog(event2);
    requestId2 = parsed.args.requestId;
    console.log("📝 Request ID:", requestId2.toString());
  }

  // Test 3: Deploy callback contract and request with callback
  console.log("\n" + "=".repeat(70));
  console.log("🎲 Test 3: Request Random Number with Callback");
  console.log("=".repeat(70));

  // Deploy a simple callback contract
  console.log("📦 Deploying test callback contract...");
  const TestCallback = await hre.ethers.getContractFactory("TestRNGCallback");
  const callback = await TestCallback.deploy(contractAddress);
  await callback.waitForDeployment();
  const callbackAddress = await callback.getAddress();
  console.log("✅ Callback contract deployed:", callbackAddress);

  // Request random number with callback
  const tx3 = await RNG.requestRandomWithCallback(100, callbackAddress);
  const receipt3 = await tx3.wait();
  console.log("✅ Transaction:", receipt3.hash);

  const event3 = receipt3.logs.find(log => {
    try {
      const parsed = RNG.interface.parseLog(log);
      return parsed && parsed.name === "RandomNumberRequested";
    } catch { return false; }
  });

  let requestId3;
  if (event3) {
    const parsed = RNG.interface.parseLog(event3);
    requestId3 = parsed.args.requestId;
    console.log("📝 Request ID:", requestId3.toString());
    console.log("   Callback Contract:", parsed.args.callbackContract);
  }

  // Test 4: Request range random numbers with callback
  console.log("\n" + "=".repeat(70));
  console.log("🎲 Test 4: Request Random Range with Callback (1-10, count=5)");
  console.log("=".repeat(70));

  const tx4 = await RNG.requestRandomRangeWithCallback(1, 10, 5, callbackAddress);
  const receipt4 = await tx4.wait();
  console.log("✅ Transaction:", receipt4.hash);

  const event4 = receipt4.logs.find(log => {
    try {
      const parsed = RNG.interface.parseLog(log);
      return parsed && parsed.name === "RandomNumberRequested";
    } catch { return false; }
  });

  let requestId4;
  if (event4) {
    const parsed = RNG.interface.parseLog(event4);
    requestId4 = parsed.args.requestId;
    console.log("📝 Request ID:", requestId4.toString());
    console.log("   Callback Contract:", parsed.args.callbackContract);
  }

  // Query request status
  console.log("\n" + "=".repeat(70));
  console.log("🔍 Checking Request Status");
  console.log("=".repeat(70));

  if (requestId1) {
    const req1 = await RNG.getRequest(requestId1);
    console.log("\nRequest", requestId1.toString() + ":");
    console.log("   Status:", getStatusName(req1.status));
    console.log("   Requester:", req1.requester);
    console.log("   Callback:", req1.callbackContract || "None");
    console.log("   Random Numbers:", req1.randomNumbers.map(n => n.toString()));
  }

  if (requestId2) {
    const req2 = await RNG.getRequest(requestId2);
    console.log("\nRequest", requestId2.toString() + ":");
    console.log("   Status:", getStatusName(req2.status));
    console.log("   Requester:", req2.requester);
    console.log("   Callback:", req2.callbackContract || "None");
    console.log("   Random Numbers:", req2.randomNumbers.map(n => n.toString()));
  }

  if (requestId3) {
    const req3 = await RNG.getRequest(requestId3);
    console.log("\nRequest", requestId3.toString() + " (with callback):");
    console.log("   Status:", getStatusName(req3.status));
    console.log("   Requester:", req3.requester);
    console.log("   Callback:", req3.callbackContract);
    console.log("   Callback Executed:", req3.callbackExecuted);
    console.log("   Random Numbers:", req3.randomNumbers.map(n => n.toString()));
  }

  if (requestId4) {
    const req4 = await RNG.getRequest(requestId4);
    console.log("\nRequest", requestId4.toString() + " (with callback):");
    console.log("   Status:", getStatusName(req4.status));
    console.log("   Requester:", req4.requester);
    console.log("   Callback:", req4.callbackContract);
    console.log("   Callback Executed:", req4.callbackExecuted);
    console.log("   Random Numbers:", req4.randomNumbers.map(n => n.toString()));
  }

  // Get all user requests
  const userRequests = await RNG.getUserRequests(user.address);
  console.log("\n📊 Total requests by user:", userRequests.length);

  // Save callback contract address for later verification
  const callbackInfo = {
    callbackContract: callbackAddress,
    requestIds: [requestId3?.toString(), requestId4?.toString()].filter(Boolean),
    network: hre.network.name,
    deployedAt: new Date().toISOString()
  };

  const callbackInfoPath = path.join(__dirname, "../callback-test-info.json");
  fs.writeFileSync(callbackInfoPath, JSON.stringify(callbackInfo, null, 2));
  console.log("\n💾 Callback test info saved to callback-test-info.json");

  console.log("=".repeat(70));
}

function getStatusName(status) {
  const names = ["Pending", "Fulfilled", "Cancelled"];
  return names[status] || "Unknown";
}

main()
  .then(() => process.exit(0))
  .catch((error) => {
    console.error("\n❌ Error:");
    console.error(error);
    process.exit(1);
  });