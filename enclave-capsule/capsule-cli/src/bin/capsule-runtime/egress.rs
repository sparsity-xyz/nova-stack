use std::sync::Arc;

use anyhow::{Result, anyhow};
use log::info;
use tokio::task::JoinHandle;

use crate::config::Configuration;
use capsule_cli::policy::EgressPolicy;
use capsule_cli::proxy::egress_http::EnclaveHttpProxy;
use capsule_cli::runtime_vsock::RuntimeHostVsockPorts;

pub struct EgressService {
    proxy: Option<JoinHandle<()>>,
}

impl EgressService {
    pub async fn start(
        config: &Configuration,
        runtime_vsock: &RuntimeHostVsockPorts,
    ) -> Result<Self> {
        let task = if let Some(proxy_uri) = config.egress_proxy_uri()? {
            info!("Starting egress");

            let egress = config.manifest.egress.as_ref().ok_or_else(|| {
                anyhow!("invariant violated: egress proxy URI requires manifest.egress")
            })?;
            let proxy_port = proxy_uri.port_u16().ok_or_else(|| {
                anyhow!("invariant violated: egress proxy URI must include a TCP port")
            })?;
            let policy = Arc::new(EgressPolicy::new(egress));
            let host_egress_port = runtime_vsock.egress_port;

            let proxy = EnclaveHttpProxy::bind(proxy_port).await?;

            Some(tokio::task::spawn(async move {
                proxy.serve(host_egress_port, policy).await;
            }))
        } else {
            None
        };

        Ok(Self { proxy: task })
    }

    pub async fn stop(self) {
        if let Some(proxy) = self.proxy {
            proxy.abort();
            _ = proxy.await;
        }
    }
}
