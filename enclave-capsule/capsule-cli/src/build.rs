use crate::constants::{
    EIF_FILE_NAME, ENCLAVE_CAPSULE_RUNTIME_PATH, ENCLAVE_CONFIG_DIR, MANIFEST_FILE_NAME,
    RELEASE_BUNDLE_DIR,
};
use crate::images::{FileBuilder, FileSource, ImageManager, ImageRef, LayerBuilder};
use crate::manifest::{Manifest, load_manifest};
use crate::nitro_cli::{EIFInfo, KnownIssue};
use crate::nitro_cli_container::NitroCLIContainer;
pub use crate::nitro_cli_container::SigningInfo;
use anyhow::{Result, anyhow};
use bollard::Docker;
use bollard::models::ImageConfig;
use bollard::query_parameters::RemoveImageOptions;
use futures_util::stream::StreamExt;
use log::{debug, info, warn};
use std::path::PathBuf;
use std::sync::Arc;
use tempfile::TempDir;
use tokio::fs::{File, canonicalize, create_dir_all, rename};
use tokio::io::AsyncWriteExt;
use uuid::Uuid;
const ENCLAVE_OVERLAY_CHOWN: &str = "0:0";
const RELEASE_OVERLAY_CHOWN: &str = "0:0";

const NITRO_CLI_IMAGE: &str = "public.ecr.aws/d4t4u8d2/sparsity-ai/nitro-cli:latest";
const CAPSULE_RUNTIME_IMAGE: &str = "public.ecr.aws/d4t4u8d2/sparsity-ai/capsule-runtime:latest";
const CAPSULE_RUNTIME_IMAGE_BINARY_PATH: &str = "/usr/local/bin/capsule-runtime";
const CAPSULE_SHELL_IMAGE: &str = "public.ecr.aws/d4t4u8d2/sparsity-ai/capsule-shell:latest";

pub struct EnclaveArtifactBuilder {
    docker: Arc<Docker>,
    image_manager: ImageManager,
    pull_tags: bool,
}

impl EnclaveArtifactBuilder {
    pub fn new(pull_tags: bool) -> Result<Self> {
        let docker_client = Arc::new(
            Docker::connect_with_local_defaults()
                .map_err(|e| anyhow!("connecting to docker: {}", e))?,
        );

        Ok(Self {
            pull_tags,
            docker: docker_client.clone(),
            image_manager: ImageManager::new_with_docker(docker_client)?,
        })
    }

    /// Build a release image based on the referenced manifest.
    pub async fn build_release(
        &self,
        manifest_path: &str,
    ) -> Result<(EIFInfo, ResolvedSources, ImageRef)> {
        let ibr = self.common_build(manifest_path).await?;
        let eif_path = ibr.build_dir.path().join(EIF_FILE_NAME);
        let mut release_img = self
            .package_eif(eif_path, manifest_path, &ibr.resolved_sources)
            .await?;

        let release_tag = &ibr.manifest.target;
        release_img.name = Some(release_tag.to_string());

        self.image_manager
            .tag_image(&release_img, release_tag)
            .await?;

        Ok((ibr.eif_info, ibr.resolved_sources, release_img))
    }

    /// Build an EIF, as would be included in a release image, based on the referenced manifest.
    pub async fn build_eif_only(
        &self,
        manifest_path: &str,
        dst_path: &str,
    ) -> Result<(EIFInfo, PathBuf)> {
        let ibr = self.common_build(manifest_path).await?;
        let eif_path = ibr.build_dir.path().join(EIF_FILE_NAME);
        rename(&eif_path, dst_path).await?;

        Ok((ibr.eif_info, canonicalize(dst_path).await?))
    }

    /// Load the referenced manifest, amend the image it references to match what we expect in
    /// an enclave, then convert the resulting image to an EIF.
    async fn common_build(&self, manifest_path: &str) -> Result<IntermediateBuildResult> {
        let manifest = load_manifest(manifest_path).await?;

        self.analyze_manifest(&manifest);

        let resolved_sources = self.resolve_sources(&manifest).await?;

        let amended_img = self
            .amend_source_image(&resolved_sources, manifest_path)
            .await?;

        info!("built intermediate image: {}", amended_img);

        let build_dir = TempDir::new()?;

        let sign: Option<SigningInfo> = if let Some(signature) = &manifest.signature {
            if let Some(parent_path) = PathBuf::from(manifest_path).parent() {
                Some(SigningInfo {
                    certificate: canonicalize(parent_path.join(&signature.certificate)).await?,
                    key: canonicalize(parent_path.join(&signature.key)).await?,
                })
            } else {
                return Err(anyhow!("Failed to get parent path of manifest"));
            }
        } else {
            None
        };

        let eif_info = self
            .image_to_eif(
                &amended_img,
                resolved_sources.nitro_cli.clone(),
                &build_dir,
                EIF_FILE_NAME,
                sign,
            )
            .await?;

        Ok(IntermediateBuildResult {
            manifest,
            resolved_sources,
            build_dir,
            eif_info,
        })
    }

    /// Amend a source image by adding one or more layers containing the files we expect
    /// to have within the enclave.
    async fn amend_source_image(
        &self,
        sources: &ResolvedSources,
        manifest_path: &str,
    ) -> Result<ImageRef> {
        let img_config = self
            .docker
            .inspect_image(sources.app.to_str())
            .await?
            .config;

        // Find the CMD and ENTRYPOINT from the source image. If either was specified in "shell form"
        // Docker seems to convert it to "exec form" as an actual shell invocation, so we can simply
        // ignore that possibility.
        //
        // Since the enclave image cannot take any arguments (which would normally override a CMD),
        // we can simply take everything from CMD and append it to the ENTRYPOINT, then append that
        // whole thing to the capsule-runtime invocation.
        // TODO(russell_h): Figure out what happens when a source image specifies env variables.
        let mut cmd = match img_config {
            Some(ImageConfig {
                cmd: Some(ref cmd), ..
            }) => cmd.clone(),
            _ => vec![],
        };

        let mut entrypoint = match img_config {
            Some(ImageConfig {
                entrypoint: Some(ref entrypoint),
                ..
            }) => entrypoint.clone(),
            _ => vec![],
        };

        let working_dir = match img_config {
            Some(ImageConfig {
                working_dir: Some(ref working_dir),
                ..
            }) => Some(working_dir.clone()),
            _ => None,
        };

        let mut capsule_runtime_command = vec![
            String::from(ENCLAVE_CAPSULE_RUNTIME_PATH),
            String::from("--config-dir"),
            String::from("/etc/capsule"),
        ];

        if let Some(wd) = working_dir {
            capsule_runtime_command.push(String::from("--work-dir"));
            capsule_runtime_command.push(wd);
        }

        capsule_runtime_command.push(String::from("--"));

        capsule_runtime_command.append(&mut entrypoint);
        capsule_runtime_command.append(&mut cmd);

        debug!("appending layer to source image");
        let amended_image = self
            .image_manager
            .append_layer(
                &sources.app,
                LayerBuilder::new()
                    .append_file(FileBuilder {
                        path: PathBuf::from(ENCLAVE_CONFIG_DIR).join(MANIFEST_FILE_NAME),
                        source: FileSource::Local {
                            path: PathBuf::from(manifest_path),
                        },
                        chown: ENCLAVE_OVERLAY_CHOWN.to_string(),
                    })
                    .append_file(FileBuilder {
                        path: PathBuf::from(ENCLAVE_CAPSULE_RUNTIME_PATH),
                        source: FileSource::Image {
                            name: sources.capsule_runtime.to_string(),
                            path: CAPSULE_RUNTIME_IMAGE_BINARY_PATH.into(),
                        },
                        chown: ENCLAVE_OVERLAY_CHOWN.to_string(),
                    })
                    .set_entrypoint(capsule_runtime_command),
            )
            .await?;

        Ok(amended_image)
    }

    /// Convert an EIF file into a release OCI image.
    ///
    /// TODO: this currently is incomplete; file permissions are wrong, the base image
    /// doesn't match our current requirements, and the exact intended format is still
    /// TBD.
    async fn package_eif(
        &self,
        eif_path: PathBuf,
        manifest_path: &str,
        sources: &ResolvedSources,
    ) -> Result<ImageRef> {
        info!("packaging EIF into release image");
        debug!("EIF file: {}", eif_path.to_string_lossy());

        let packaged_img = self
            .image_manager
            .append_layer(
                &sources.capsule_shell,
                LayerBuilder::new()
                    .append_file(FileBuilder {
                        path: PathBuf::from(RELEASE_BUNDLE_DIR).join(MANIFEST_FILE_NAME),
                        source: FileSource::Local {
                            path: PathBuf::from(manifest_path),
                        },
                        chown: RELEASE_OVERLAY_CHOWN.to_string(),
                    })
                    .append_file(FileBuilder {
                        path: PathBuf::from(RELEASE_BUNDLE_DIR).join(EIF_FILE_NAME),
                        source: FileSource::Local { path: eif_path },
                        chown: RELEASE_OVERLAY_CHOWN.to_string(),
                    }),
            )
            .await?;

        Ok(packaged_img)
    }

    async fn write_nitro_cli_docker_context(
        build_dir: &TempDir,
        source_image_ref: &str,
    ) -> Result<PathBuf> {
        let docker_context_dir = build_dir.path().join("docker-context");
        create_dir_all(&docker_context_dir).await?;

        let dockerfile_path = docker_context_dir.join("Dockerfile");
        let mut dockerfile = File::create(&dockerfile_path).await?;
        dockerfile
            .write_all(format!("FROM {source_image_ref}\n").as_bytes())
            .await?;
        dockerfile.flush().await?;
        dockerfile.shutdown().await?;

        Ok(docker_context_dir)
    }

    /// Convert the referenced image to an EIF file, which will be deposited into `build_dir`
    /// using the file name `eif_name`.
    ///
    /// This operates by mounting the build dir into a docker container, and invoking `nitro-cli build-enclave`
    /// inside that container.
    async fn image_to_eif(
        &self,
        source_img: &ImageRef,
        nitro_cli_img: ImageRef,
        build_dir: &TempDir,
        eif_name: &str,
        sign: Option<SigningInfo>,
    ) -> Result<EIFInfo> {
        let build_dir_path = build_dir.path().to_str().unwrap();

        // nitro-cli build-enclave can build from a Dockerfile directory. Tag the amended
        // image locally once, then build a tiny Docker context that simply FROMs that
        // local tag so Nitro CLI stays on the local-daemon path instead of probing
        // remote registries for a temporary image name.
        let source_tag = format!("capsule-intermediate-{}", Uuid::new_v4());
        let source_image_ref = format!("{source_tag}:latest");
        self.image_manager
            .tag_image(source_img, &source_tag)
            .await?;

        let docker_context_dir =
            Self::write_nitro_cli_docker_context(build_dir, &source_image_ref).await?;
        debug!(
            "tagged intermediate image: {} and wrote docker context: {}",
            source_image_ref,
            docker_context_dir.to_string_lossy()
        );

        let nitro_cli = NitroCLIContainer::new(self.docker.clone(), nitro_cli_img);
        let docker_uri = format!("capsule-eif-build-{}:latest", Uuid::new_v4());
        let build_container_id = nitro_cli
            .build_enclave(
                eif_name,
                &docker_uri,
                "/build/docker-context",
                build_dir_path,
                sign,
            )
            .await?;

        info!(
            "started nitro-cli build-eif in container: {}",
            build_container_id
        );

        // Convert docker output to log lines, to give the user some feedback as to what is going on.
        let mut detected_nitro_cli_issue = None;

        let mut stderr_stream = nitro_cli.stderr(&build_container_id, true);
        while let Some(line) = stderr_stream.next().await {
            // Note that these come with trailing newlines, which we trim off.
            let trimmed = line.trim_end();

            if detected_nitro_cli_issue.is_none() {
                detected_nitro_cli_issue = KnownIssue::detect(&line);
            }

            info!(target: "nitro-cli::build-eif", "{trimmed}");
        }

        if let Some(issue) = detected_nitro_cli_issue {
            warn!(
                "detected known nitro-cli issue:\n{}",
                issue.helpful_message()
            );
        }

        let mut json_buf = Vec::with_capacity(4096);
        let status_code = nitro_cli.wait_container(&build_container_id).await?;

        if status_code == 0 {
            let mut stdout_stream = nitro_cli.stdout(&build_container_id, false);

            while let Some(line) = stdout_stream.next().await {
                json_buf.extend_from_slice(line.as_ref());
            }
        }

        // Always attempt cleanup, even when nitro-cli exits non-zero, so repeated
        // builds do not accumulate temporary container/image state in the daemon.
        let remove_container_result = nitro_cli.remove_container(&build_container_id).await;
        let _ = self
            .docker
            .remove_image(&docker_uri, None::<RemoveImageOptions>, None)
            .await;
        let _ = self
            .docker
            .remove_image(&source_image_ref, None::<RemoveImageOptions>, None)
            .await;

        remove_container_result?;

        if status_code != 0 {
            return Err(anyhow!("non-zero exit code from nitro-cli",));
        }

        Ok(serde_json::from_slice(&json_buf)?)
    }

    fn analyze_manifest(&self, manifest: &Manifest) {
        if manifest.ingress.is_none() {
            info!(
                "no ingress specified in manifest; there will be no way to connect to this enclave"
            );
        }

        if manifest.egress.is_none() {
            info!(
                "no egress specified in manifest; this enclave will have no outbound network access"
            );
        }
    }

    // External images are images whose tags we do not normally manage. In other words,
    // a user tags an image, then gives us that tag - and unless specifically instructed
    // otherwise we should not overwrite that tag.
    async fn resolve_external_source_image(&self, image_name: &str) -> Result<ImageRef> {
        if self.pull_tags {
            self.image_manager.pull_image(image_name).await
        } else {
            self.image_manager.find_or_pull(image_name).await
        }
    }

    async fn resolve_internal_source_image(
        &self,
        name_override: Option<&str>,
        default: &str,
    ) -> Result<ImageRef> {
        // Internal runtime images now follow the same local-first behavior as app
        // images unless the user explicitly asks for --pull. This keeps default
        // builds reproducible against preloaded images, while preserving an escape
        // hatch for callers that want to refresh latest-tag defaults.
        let (image_name, mut img) = match name_override {
            Some(image_name) => (
                image_name,
                self.image_manager.find_or_pull(image_name).await?,
            ),
            None => {
                let img = if self.pull_tags {
                    self.image_manager.pull_image(default).await?
                } else {
                    self.image_manager.find_or_pull(default).await?
                };
                (default, img)
            }
        };

        img.name = Some(image_name.to_string());
        Ok(img)
    }

    async fn resolve_sources(&self, manifest: &Manifest) -> Result<ResolvedSources> {
        let app = self
            .resolve_external_source_image(&manifest.sources.app)
            .await?;
        info!("using app image: {app}");

        let capsule_runtime = self
            .resolve_internal_source_image(
                manifest.sources.capsule_runtime.as_deref(),
                CAPSULE_RUNTIME_IMAGE,
            )
            .await?;
        if manifest.sources.capsule_runtime.is_none() {
            debug!("no supervisor image specified in manifest; using default: {capsule_runtime}");
        } else {
            info!("using supervisor image: {capsule_runtime}");
        }

        let release_base = self
            .resolve_internal_source_image(
                manifest.sources.capsule_shell.as_deref(),
                CAPSULE_SHELL_IMAGE,
            )
            .await?;
        if manifest.sources.capsule_shell.is_none() {
            debug!(
                "no capsule-shell base image specified in manifest; using default: {release_base}"
            );
        } else {
            info!("using capsule-shell base image: {release_base}");
        }

        let nitro_cli = self
            .resolve_internal_source_image(None, NITRO_CLI_IMAGE)
            .await?;
        info!("using nitro-cli image: {nitro_cli}");

        let sources = ResolvedSources {
            app,
            capsule_runtime,
            nitro_cli,
            capsule_shell: release_base,
        };

        Ok(sources)
    }
}

struct IntermediateBuildResult {
    manifest: Manifest,
    resolved_sources: ResolvedSources,
    build_dir: TempDir,
    eif_info: EIFInfo,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct ResolvedSources {
    #[serde(rename = "App")]
    app: ImageRef,

    #[serde(rename = "CapsuleRuntime")]
    capsule_runtime: ImageRef,

    #[serde(rename = "NitroCLI")]
    nitro_cli: ImageRef,

    #[serde(rename = "CapsuleShell")]
    capsule_shell: ImageRef,
}

#[cfg(test)]
mod tests {
    // Intentionally strict: these tests treat selected docs/workflows/scripts
    // as part of the product contract, so CI fails fast when code and
    // user-facing operational guidance drift apart.
    use super::{EnclaveArtifactBuilder, NITRO_CLI_IMAGE};
    use std::fs;
    use std::path::{Path, PathBuf};
    use tempfile::TempDir;

    fn nitro_cli_image_repo() -> String {
        NITRO_CLI_IMAGE
            .strip_suffix(":latest")
            .expect("nitro-cli default image should use the latest tag")
            .to_string()
    }

    fn repo_root() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("capsule-cli crate should live under repository root")
            .to_path_buf()
    }

    fn collect_doc_files(path: &Path, files: &mut Vec<PathBuf>) {
        if path.is_dir() {
            for entry in
                fs::read_dir(path).unwrap_or_else(|err| panic!("reading directory {path:?}: {err}"))
            {
                let entry = entry
                    .unwrap_or_else(|err| panic!("reading directory entry in {path:?}: {err}"));
                collect_doc_files(&entry.path(), files);
            }
            return;
        }

        let Some(extension) = path.extension().and_then(|ext| ext.to_str()) else {
            return;
        };

        if matches!(extension, "md" | "yaml" | "yml") {
            files.push(path.to_path_buf());
        }
    }

    #[test]
    fn default_nitro_cli_image_uses_self_hosted_public_ecr() {
        assert_eq!(
            NITRO_CLI_IMAGE,
            "public.ecr.aws/d4t4u8d2/sparsity-ai/nitro-cli:latest"
        );
        assert_eq!(
            nitro_cli_image_repo(),
            "public.ecr.aws/d4t4u8d2/sparsity-ai/nitro-cli"
        );
    }

    #[test]
    fn capsule_shell_dockerfiles_default_to_same_nitro_cli_image() {
        for rel_path in [
            "dockerfiles/capsule-shell-dev.dockerfile",
            "dockerfiles/capsule-shell-release.dockerfile",
        ] {
            let path = repo_root().join(rel_path);
            let contents =
                fs::read_to_string(&path).unwrap_or_else(|err| panic!("reading {path:?}: {err}"));

            assert!(
                contents.contains(&format!("ARG NITRO_CLI_IMAGE={NITRO_CLI_IMAGE}")),
                "{rel_path} should default to {NITRO_CLI_IMAGE}"
            );
            assert!(
                contents.contains("FROM ${NITRO_CLI_IMAGE} AS nitro_cli"),
                "{rel_path} should source nitro-cli from the overridable build arg"
            );
        }
    }

    #[test]
    fn nitro_cli_dockerfile_rebuilds_fuse_enabled_blobs() {
        let path = repo_root().join("dockerfiles/nitro-cli.dockerfile");
        let contents =
            fs::read_to_string(&path).unwrap_or_else(|err| panic!("reading {path:?}: {err}"));

        assert!(
            contents.contains("aws-nitro-enclaves-sdk-bootstrap"),
            "nitro-cli image should rebuild the official Nitro Enclaves blobs from source"
        );
        assert!(
            contents.contains("CONFIG_FUSE_FS=y"),
            "nitro-cli image should enable FUSE in the rebuilt enclave kernel config"
        );
        assert!(
            contents.contains("sed -i -E"),
            "nitro-cli image should rewrite the upstream kernel config before rebuilding blobs"
        );
        assert!(
            contents.contains("s|^CONFIG_FUSE_FS=.*$|CONFIG_FUSE_FS=y|"),
            "nitro-cli image should force any existing CONFIG_FUSE_FS setting to CONFIG_FUSE_FS=y"
        );
        assert!(
            contents.contains("test -s \"${kernel_image}\""),
            "nitro-cli image should verify that the rebuilt kernel binary exists before publishing the blobs"
        );
    }

    #[test]
    fn nitro_cli_validation_script_checks_fuse_and_smoke_builds_eif() {
        let path = repo_root().join("scripts/validate-nitro-cli-image.sh");
        let contents =
            fs::read_to_string(&path).unwrap_or_else(|err| panic!("reading {path:?}: {err}"));

        assert!(
            contents.contains("CONFIG_FUSE_FS"),
            "validation script should verify that the nitro-cli kernel enables FUSE"
        );
        assert!(
            contents.contains("build-enclave"),
            "validation script should run a smoke EIF build"
        );
    }

    #[test]
    fn capsule_cli_build_smoke_script_exercises_docker_dir_path() {
        let path = repo_root().join("scripts/capsule-build-smoke-test.sh");
        let contents =
            fs::read_to_string(&path).unwrap_or_else(|err| panic!("reading {path:?}: {err}"));

        assert!(
            contents.contains("\"${CAPSULE_CLI_BIN}\" -v build -f"),
            "smoke test should execute capsule-cli build through the CLI entrypoint"
        );
        assert!(
            contents.contains("wrote docker context"),
            "smoke test should assert that capsule-cli used the docker-dir Nitro CLI path"
        );
        assert!(
            contents.contains("CAPSULE_CLI_SMOKE_MODE")
                && contents.contains("Preparing local fixture images for smoke mode"),
            "smoke test should support a fixture mode for rate-limit-resistant CI coverage"
        );
        assert!(
            contents.contains("uuidgen")
                || contents.contains("openssl rand -hex")
                || contents.contains("printf '%s-%s'"),
            "smoke test should use a high-entropy tag suffix strategy with a safe fallback"
        );
        assert!(
            contents.contains("no manifest")
                && contents.contains("overwrite any pre-existing local copy"),
            "smoke test should document why fixture mode temporarily reuses the published nitro-cli tag"
        );
        assert!(
            contents.contains("/enclave/application.eif")
                && contents.contains("/enclave/capsule.yaml"),
            "smoke test should verify the release image contains the packaged EIF bundle"
        );
    }

    #[tokio::test]
    async fn nitro_cli_docker_dir_context_uses_local_tag_reference() {
        let build_dir = TempDir::new().expect("temp dir should be created");
        let docker_context_dir = EnclaveArtifactBuilder::write_nitro_cli_docker_context(
            &build_dir,
            "capsule-intermediate-test:latest",
        )
        .await
        .expect("docker context should be created");

        let dockerfile_path = docker_context_dir.join("Dockerfile");
        let contents = fs::read_to_string(&dockerfile_path)
            .unwrap_or_else(|err| panic!("reading {dockerfile_path:?}: {err}"));

        assert_eq!(contents, "FROM capsule-intermediate-test:latest\n");
    }

    #[test]
    fn nitro_cli_workflow_publishes_and_validates_self_hosted_image() {
        let path = repo_root().join(".github/workflows/nitro-cli.yaml");
        let contents =
            fs::read_to_string(&path).unwrap_or_else(|err| panic!("reading {path:?}: {err}"));

        assert!(
            contents.contains(&format!("NITRO_CLI_IMAGE: {}", nitro_cli_image_repo())),
            "nitro-cli workflow should publish the self-hosted nitro-cli repository"
        );
        assert!(
            contents.contains("scripts/validate-nitro-cli-image.sh"),
            "nitro-cli workflow should validate the nitro-cli image before publishing it"
        );
        assert!(
            contents.contains("platforms: linux/amd64"),
            "nitro-cli workflow should publish only linux/amd64"
        );
        assert!(
            !contents.contains("linux/amd64,linux/arm64"),
            "nitro-cli workflow should not publish linux/arm64"
        );
        assert!(
            contents.contains("cache-from: type=gha,scope=nitro-cli-amd64"),
            "nitro-cli workflow should reuse the validated build cache for the push build"
        );
        assert!(
            contents.contains("cache-to: type=gha,mode=max,scope=nitro-cli-amd64"),
            "nitro-cli workflow should export the nitro-cli build cache between validation and push"
        );
    }

    #[test]
    fn ci_workflow_runs_capsule_cli_build_smoke_test() {
        let path = repo_root().join(".github/workflows/ci.yaml");
        let contents =
            fs::read_to_string(&path).unwrap_or_else(|err| panic!("reading {path:?}: {err}"));

        assert!(
            contents.contains("Smoke test capsule-cli build"),
            "CI workflow should include the end-to-end capsule-cli build smoke test job step"
        );
        assert!(
            contents.contains("CAPSULE_CLI_SMOKE_MODE: fixture"),
            "CI workflow should run the smoke test in fixture mode to avoid registry rate limits"
        );
        assert!(
            contents.contains("timeout-minutes: 15"),
            "CI workflow should time out the smoke job instead of relying on the platform default"
        );
        assert!(
            contents.contains("./scripts/capsule-build-smoke-test.sh"),
            "CI workflow should execute the capsule-cli build smoke test script"
        );
    }

    #[test]
    fn nitro_cli_publish_script_is_amd64_only() {
        let path = repo_root().join("scripts/build-and-publish-nitro-cli.sh");
        let contents =
            fs::read_to_string(&path).unwrap_or_else(|err| panic!("reading {path:?}: {err}"));

        assert!(
            contents.contains("VALIDATION_PLATFORM=\"linux/amd64\""),
            "nitro-cli publish script should validate only linux/amd64"
        );
        assert!(
            contents.contains("PUBLISH_PLATFORM=\"linux/amd64\""),
            "nitro-cli publish script should publish only linux/amd64"
        );
        assert!(
            contents.contains("currently supported only on x86_64 hosts"),
            "nitro-cli publish script should reject non-x86_64 hosts"
        );
        assert!(
            !contents.contains("linux/amd64,linux/arm64"),
            "nitro-cli publish script should not publish linux/arm64"
        );
        assert!(
            contents.contains("--cache-to \"type=local,dest=${BUILD_CACHE_DIR},mode=max\""),
            "nitro-cli publish script should save the validated build cache before the push build"
        );
        assert!(
            contents.contains("--cache-from \"type=local,src=${BUILD_CACHE_DIR}\""),
            "nitro-cli publish script should reuse the validated build cache for the push build"
        );
    }

    #[test]
    fn release_workflow_matches_current_amd64_only_release_contract() {
        let path = repo_root().join(".github/workflows/release.yaml");
        let contents =
            fs::read_to_string(&path).unwrap_or_else(|err| panic!("reading {path:?}: {err}"));

        assert!(
            !contents.contains("Build Nitro CLI Image"),
            "release workflow should not publish nitro-cli automatically"
        );
        assert!(
            !contents.contains("scripts/validate-nitro-cli-image.sh"),
            "release workflow should not run the manual nitro-cli validation/publish flow"
        );
        assert!(
            contents.contains("target: 'x86_64-unknown-linux-musl'"),
            "release workflow should still build the x86_64 release binaries"
        );
        assert!(
            !contents.contains("target: 'aarch64-unknown-linux-musl'"),
            "release workflow should not build aarch64 release binaries"
        );
        assert!(
            contents.contains("mv x86_64-unknown-linux-musl amd64"),
            "release workflow should rearrange only the x86_64 release artifacts for image publishing"
        );
        assert!(
            !contents.contains("mv aarch64-unknown-linux-musl arm64"),
            "release workflow should not rearrange arm64 release artifacts"
        );

        let mut current_file = None;
        let mut capsule_runtime_platforms = None;
        let mut capsule_shell_platforms = None;
        for line in contents.lines() {
            let trimmed = line.trim();
            if let Some(rest) = trimmed.strip_prefix("file:") {
                current_file = Some(rest.trim());
                continue;
            }

            let Some(rest) = trimmed.strip_prefix("platforms:") else {
                continue;
            };

            match current_file {
                Some("capsule-runtime-release.dockerfile") => {
                    capsule_runtime_platforms = Some(rest.trim())
                }
                Some("capsule-shell-release.dockerfile") => {
                    capsule_shell_platforms = Some(rest.trim())
                }
                _ => {}
            }
        }

        assert!(
            capsule_runtime_platforms == Some("linux/amd64"),
            "release workflow should publish capsule-runtime only for linux/amd64"
        );
        assert!(
            !capsule_runtime_platforms.is_some_and(|platforms| platforms.contains("linux/arm64")),
            "release workflow should not try to publish capsule-runtime for linux/arm64"
        );
        assert!(
            capsule_shell_platforms == Some("linux/amd64"),
            "release workflow should publish capsule-shell only for linux/amd64 because nitro-cli is linux/amd64 only"
        );
        assert!(
            !capsule_shell_platforms.is_some_and(|platforms| platforms.contains("linux/arm64")),
            "release workflow should not try to publish capsule-shell for linux/arm64"
        );
    }

    #[test]
    fn documentation_describes_current_hostfs_and_nitro_cli_model() {
        // Intentionally strict: these checks pin the user-facing docs to the
        // current runtime/deployment contract so doc drift fails fast in CI.
        let root = repo_root();
        let read = |rel_path: &str| {
            let path = root.join(rel_path);
            fs::read_to_string(&path).unwrap_or_else(|err| panic!("reading {path:?}: {err}"))
        };

        let readme = read("README.md");
        assert!(
            readme.contains("## Nova Enclave Capsule Highlights"),
            "README should summarize Nova Enclave Capsule's core capabilities in a dedicated highlights section"
        );
        assert!(
            readme.contains("[Host-Backed Directory Mounts Guide](docs/host_backed_mounts.md)"),
            "README should point readers to the dedicated host-backed mounts guide instead of inlining the feature details"
        );

        let hostfs_doc = read("docs/host_backed_mounts.md");
        assert!(
            hostfs_doc.to_ascii_lowercase().contains("host-backed")
                && hostfs_doc
                    .to_ascii_lowercase()
                    .contains("temporary directory"),
            "hostfs design doc should describe the temporary-directory behavior without relying on external product naming"
        );
        assert!(
            hostfs_doc.contains("Whether the mount behaves as \"temporary\" or \"persistent\""),
            "hostfs design doc should explain that persistence depends on host_state_dir reuse"
        );
        assert!(
            !hostfs_doc.contains("Nova Platform") && !hostfs_doc.contains("/opt/nova/"),
            "hostfs design doc should avoid Nova Platform-specific naming or example paths"
        );

        let cli_doc = read("docs/capsule-cli.md");
        assert!(
            cli_doc.contains("hostfs file proxy"),
            "CLI docs should explain that --mount uses the hostfs file proxy"
        );
        assert!(
            cli_doc.contains("separate `capsule-cli run` processes can coexist on the same EC2"),
            "CLI docs should document the current multi-instance runtime support"
        );

        let port_doc = read("docs/port_handling.md");
        assert!(
            port_doc
                .contains("Multiple `capsule-cli run` processes can run on the same EC2 instance"),
            "port handling docs should call out the current multi-instance runtime support"
        );
        assert!(
            port_doc.contains("20000 + (CID * 128) + 0"),
            "port handling docs should describe the CID-derived host-side egress port formula"
        );
        assert!(
            port_doc.contains("20000 + (CID * 128) + 16 + N"),
            "port handling docs should describe the CID-derived host-side hostfs port formula"
        );

        let base_images_doc = read("docs/base-images.md");
        assert!(
            base_images_doc.contains("linux/amd64"),
            "base image docs should state that Nitro CLI publishing is linux/amd64 only"
        );
        assert!(
            base_images_doc
                .contains("published Capsule Runtime image is currently `linux/amd64` only"),
            "base image docs should state that Capsule Runtime publishing is currently linux/amd64 only"
        );
        assert!(
            base_images_doc
                .contains("published Capsule Shell image is currently `linux/amd64` only"),
            "base image docs should state that Capsule Shell publishing is currently linux/amd64 only"
        );

        let image_build_doc = read("docs/building_images_guidance.md");
        assert!(
            image_build_doc.contains("The helper is currently `x86_64`-only"),
            "image build docs should explain that the default local capsule-shell helper currently requires x86_64"
        );
        assert!(
            image_build_doc.contains("--file dockerfiles/capsule-runtime-release.dockerfile")
                && image_build_doc.contains("--platform linux/amd64")
                && image_build_doc.contains("-t capsule-runtime:local ."),
            "image build docs should show capsule-runtime release builds as linux/amd64 only"
        );
        assert!(
            image_build_doc.contains("--file dockerfiles/capsule-shell-release.dockerfile")
                && image_build_doc.contains("--platform linux/amd64")
                && image_build_doc.contains("-t capsule-shell:local ."),
            "image build docs should show capsule-shell release builds as linux/amd64 only"
        );
        assert!(
            image_build_doc.contains("scripts/capsule-build-smoke-test.sh"),
            "image build docs should document the capsule-cli build smoke test helper"
        );
        assert!(
            image_build_doc.contains("CAPSULE_CLI_SMOKE_MODE=fixture"),
            "image build docs should document the fixture-based smoke test mode"
        );

        let ci_doc = read("docs/ci.md");
        assert!(
            !ci_doc.contains("aarch64-unknown-linux-musl"),
            "CI docs should not describe aarch64 release binaries anymore"
        );
        assert!(
            ci_doc
                .contains("packages only the `x86_64` `capsule-cli` binary into a release tarball"),
            "CI docs should describe the x86_64-only release artifact packaging"
        );
        assert!(
            ci_doc.contains("CAPSULE_CLI_SMOKE_MODE=fixture")
                && ci_doc.contains("scripts/capsule-build-smoke-test.sh"),
            "CI docs should describe the capsule-cli build smoke test helper"
        );

        let nitro_cli_doc = read("docs/nitro_cli_fuse_image.md");
        assert!(
            nitro_cli_doc.contains("hostfs file proxy"),
            "nitro-cli doc should explain why FUSE is needed for the hostfs file proxy"
        );
        assert!(
            nitro_cli_doc.contains("linux/amd64"),
            "nitro-cli doc should document the current publish architecture"
        );
        assert!(
            !nitro_cli_doc.contains("Nova Platform"),
            "nitro-cli doc should avoid Nova Platform-specific naming for host-backed mounts"
        );

        let capsule_runtime_doc = read("docs/capsule-runtime.md");
        assert!(
            !capsule_runtime_doc.contains("/opt/nova/"),
            "Capsule Runtime docs should avoid Nova Platform-specific example paths for host-backed mounts"
        );

        let architecture_doc = read("docs/architecture.md");
        assert!(
            architecture_doc.contains("host-side vsock port derived from the enclave CID"),
            "architecture docs should describe that host-side runtime ports are derived from the enclave CID"
        );

        let detailed_architecture_doc = read("docs/capsule-architecture.md");
        assert!(
            detailed_architecture_doc.contains("20000 + (CID * 128) + 0"),
            "detailed architecture docs should list the CID-derived egress port formula"
        );

        let hn_fetcher_doc = read("examples/hn-fetcher/readme.md");
        assert!(
            hn_fetcher_doc.contains("#capsule-runtime: \"capsule-runtime:latest\""),
            "hn-fetcher example README should match the checked-in example manifest's capsule-runtime override comment"
        );
        assert!(
            hn_fetcher_doc.contains("curl http://localhost:9001/v1/encryption/public_key"),
            "hn-fetcher example README should document the aux API encryption public key endpoint"
        );
        assert!(
            hn_fetcher_doc.contains("removing `public_key` before forwarding")
                && hn_fetcher_doc.contains("`nonce` and `user_data` are preserved"),
            "hn-fetcher example README should describe the current aux API attestation sanitization behavior"
        );
    }

    #[test]
    fn documentation_only_keeps_the_upstream_repo_link() {
        let root = repo_root();
        let mut files = Vec::new();

        for rel_path in ["README.md", "CODE_OF_CONDUCT.md", "docs", "examples"] {
            collect_doc_files(&root.join(rel_path), &mut files);
        }

        let mut violations = Vec::new();
        for path in files {
            let rel_path = path
                .strip_prefix(&root)
                .expect("doc file should live under the repository root");
            let contents =
                fs::read_to_string(&path).unwrap_or_else(|err| panic!("reading {path:?}: {err}"));

            for (line_no, line) in contents.lines().enumerate() {
                let mentions_upstream = line.contains("enclaver-io")
                    || line.contains("github.com/enclaver-io")
                    || line.contains("enclaver.io");

                if !mentions_upstream {
                    continue;
                }

                let is_allowed_repo_reference = rel_path == Path::new("README.md")
                    && line.contains(
                        "[enclaver-io/enclaver](https://github.com/enclaver-io/enclaver)",
                    );

                if !is_allowed_repo_reference {
                    violations.push(format!("{}:{}: {}", rel_path.display(), line_no + 1, line));
                }
            }
        }

        assert!(
            violations.is_empty(),
            "documentation should not reference enclaver-io outside the README upstream repo link: {}",
            violations.join(" | ")
        );
    }
}
