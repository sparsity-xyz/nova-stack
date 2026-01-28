# Price oracle demo
This is a demo showing how a price oracle runs on the Sparsity Nova Platform.

## local testing
### requirements
- anvil
- python
### deploy contract
start node
```
anvil
```
deploy
```
make deploy-contract-local
```
set mock TEE wallet
```
make register-tee-wallet TEE_WALLET=0xabe4705b049a73408c2ad6bad9296b60cb373d8a
```

### backend service
```
cd backend

python3 app.py
```

### frontend service
```
cd frontend

npm install

npm run dev
```


## deploy on Sparsity Nova Platform

### deploy contract
set up environment variables
```
cp .env.example .env

fulfill PRIVATE_KEY 
```
deploy
```
make deploy-contract
```
### go to Sparsity Nova Platform
```
https://nova.sparsity.ai/
```
create a new app and deploy
### get address inside service
after the app was registered onchain, fund the wallet inside TEE
```
curl <APP_ENDPOINT>
```
the output should be
```
{
    "balance": "0.00 ETH",
    "contract_address": "0x9fe46736679d2d9a65f0992f2272de9f3c7fa6e0",
    "enclave_address": "0x8141ed5fbd2749c7e2788ed6b3bd54b9b1b0347f",
    "endpoints": {
        "/contract-price": "Read current price from contract",
        "/price": "Get current BTC price from CoinGecko",
        "/update": "Manually trigger price update to contract"
    },
    "message": "BTC Price Oracle",
    "status": "ok"
}
```
fund `enclave_address`
