.PHONY: dev-backend dev-frontend build-frontend build-enclave

dev-backend:
	cd enclave && IN_ENCLAVE=false python3 app.py

dev-frontend:
	cd frontend && npm run dev

build-frontend:
	cd frontend && npm install && npm run build
	rm -rf enclave/frontend
	mkdir -p enclave/frontend
	cp -r frontend/dist/* enclave/frontend/

build-enclave:
	enclaver build
