const hre = require("hardhat");
const fs = require("fs");
const path = require("path");

async function main() {
    const deploymentPath = path.join(__dirname, "../rng-deployment.json");
    if (!fs.existsSync(deploymentPath)) {
        console.error("❌ Deployment info not found. Run 'npm run deploy:local' first.");
        process.exit(1);
    }

    const deployment = JSON.parse(fs.readFileSync(deploymentPath, "utf8"));
    const contractAddress = deployment.contractAddress;

    console.log("\n🎲 Requesting Random Number");
    console.log("Contract:", contractAddress);
    console.log("Network:", hre.network.name);

    const [user] = await hre.ethers.getSigners();
    const RNG = await hre.ethers.getContractAt("RandomNumberGenerator", contractAddress);

    console.log("\n👤 Requesting from:", user.address);

    // Request random number between 0-100
    const tx = await RNG.requestRandom(100);
    console.log("📝 Transaction submitted:", tx.hash);

    const receipt = await tx.wait();
    console.log("✅ Transaction confirmed in block", receipt.blockNumber);

    // Find event
    const event = receipt.logs.find(log => {
        try {
            const parsed = RNG.interface.parseLog(log);
            return parsed.name === "RandomNumberRequested";
        } catch (e) {
            return false;
        }
    });

    if (event) {
        const parsed = RNG.interface.parseLog(event);
        console.log("\n🆔 Request ID:", parsed.args.requestId.toString());
        console.log("⏰ Timestamp:", new Date(Number(parsed.args.timestamp) * 1000).toISOString());
    } else {
        console.log("\n⚠️  Event not found in logs");
    }

    console.log("\n✨ Request Sent! Run 'npm run check:local' to see status.");
}

main().catch(console.error);
