# Provenance & encoding audit • 2026-10-17

## Verified from public source files

- User-linked package `ghcr.io/aeon-7/vllm-aeon-ultimate-dflash` contains experimental DDTree image lineage, including GHCR package digest `sha256:51a5421165927db6b1ae1d347fc15b315589ab5a79a2aa4e79f13f74b45dc3a4` for a historical v5 tag. A registry manifest digest is not a hash of an LLM checkpoint and does not imply hidden weights.
- GitHub repo `AEON-7/Qwen3.6-27B-AEON-Ultimate-Uncensored-DFlash` has `Dockerfile.v3`, `AGENTS.md`, `docker-compose.yml`, `docker-compose.spark-xs.yml` and an experimental `container/qwen36-v5-ddtree-experimental/` track.
- Its current `AGENTS.md` points to **unified** `ghcr.io/aeon-7/aeon-vllm-ultimate:2026-06-18-v0.23.0-dflashfix` for DGX Spark. It warns that DDTree is experimental and not the production path.
- AEON's Spark XS baseline chooses the **modelopt** NVFP4 XS body, external z-lab DFlash drafter, `num_speculative_tokens=10`, and `--kv-cache-dtype auto` (BF16). The source explicitly rejects TurboQuant K8V4 on hybrid GDN/Mamba.
- HF source metadata locates the main model weights at `AEON-7/Qwen3.6-27B-AEON-Ultimate-Uncensored-Multimodal-NVFP4-MTP-XS` and drafter at `z-lab/Qwen3.6-27B-DFlash` — not in `SOUL.md`, the user HUD, or the CLI shell.
- Native MTP (`qwen3_5_mtp` n=3) is separately supported in designated checkpoints. It must not be mixed with the DFlash speculative decoding flags at the same time.

## Encoding inspection of supplied AXS/HUD text

- The AXS `buildUrl(...strings.protocol)` fragments `ht`,`tps`,`:`,`//` concatenate to `https://` and construct normal GitHub / Alpine CDN retrieval URLs. This is textual obfuscation, not encryption.
- The HUD `btoa('AXS_SYS_LAUNCHE_PARAM_ADDR_0x…_EXEC')` encodes a display label in Base64. `data:text/json;base64,...` does not launch a real sandbox or provide a model. The label itself is not JSON.
- `10.AXS.x.y` is not a valid literal IPv4 address; the source's `6,000` points are JavaScript objects rendered in Three.js and have no demonstrated backing 6,000 connected processes.
- AXS `envInjections` shell interpolation is vulnerable if arbitrary environment values are allowed. No code execution on untrusted values is allowed in our adapter.

## Boundaries

No access was obtained to private registry layers, embedded binary secrets, all HF weight tensor values, or the user's existing private deployment. There is **no substantiated discovery of a hidden superior model or secret codebook**. A real security audit should include pinned image digest, `docker image inspect`, software bill of materials, signature verification, and malicious file scanning on an authorized isolated machine. This artifact makes no clean bill of health assertion for unseen binary assets.

## Sources

- https://github.com/AEON-7/Qwen3.6-27B-AEON-Ultimate-Uncensored-DFlash
- https://github.com/AEON-7/Qwen3.6-27B-AEON-Ultimate-Uncensored-DFlash/blob/main/AGENTS.md
- https://github.com/AEON-7/Qwen3.6-27B-AEON-Ultimate-Uncensored-DFlash/blob/main/docker-compose.spark-xs.yml
- https://github.com/AEON-7/Qwen3.6-27B-AEON-Ultimate-Uncensored-DFlash/pkgs/container/vllm-aeon-ultimate-dflash
- https://huggingface.co/AEON-7/Qwen3.6-27B-AEON-Ultimate-Uncensored-Multimodal-NVFP4-MTP-XS
- https://huggingface.co/z-lab/Qwen3.6-27B-DFlash
