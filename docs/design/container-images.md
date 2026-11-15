# Container images: running the borrower's own image on the lender

Status: **in progress** (2026-11-15). Step 0 (safety fixes to the container runner) is built;
step 1 (sending images) is being built.

## Why

A container task runs in an image that must already be on the lender: GimmeCores never
downloads images, so today the lender's owner runs `docker pull`, or loads an image the
borrower hands over by hand (`docker save` / `docker load`). Sending the borrower's own image
over the paired link removes that step and makes "run my container on my office mate's laptop"
practical.

## Decisions (the user's, 2026-11-15)

- **First: send your image**, for one-off jobs as today. A container that stays up between
  commands (`gmc dev up`, with ports reachable from the borrower) comes later; it needs its own
  design and an experiment on Docker Desktop first, since containers have no network.
- **The lender approves once per grant, with a size cap** ("may send Docker images, up to
  N GB"), not per image: every rebuild is a new image.
- **The lender's own images: "any, but say so".** A container grant may still run any image on
  the lender; every approval says it can run and read them.

Left out for now: internet access inside containers (letting a container reach the internet but
not the lender's network is an open problem, threat model section 8), and Compose.

## Step 0: what was unsafe in the container runner (fixed)

Found while designing this; all three apply to images the lender already has, too.

1. **The lender's own images.** A container grant lets the borrower name any image on the
   lender and copy what is inside out with `--out`. Kept by the owner's choice, and now said in
   every approval (`gmc requests`, the app, the Touch ID / password prompt).
2. **The hand-back step (Linux).** Files a container task makes belong to its unprivileged
   user, so the daemon could not remove them. The old fix ran the task image's own `chown` as
   root with CAP_CHOWN: a borrower-made image could run its own code as root there. Now it runs
   the lender's own `chmod`, from the lender's system folders mounted read-only into an image
   GimmeCores makes with no program in it, as the task's own user with no capabilities. It also
   opens folders the task locked, which the old step could not.
3. **Image volumes.** A `VOLUME` in an image gave the task a writable folder on Docker's own
   disk, outside the read-only system, the memory cap and the grant's disk limit (measured: 600
   MB under a 256 MB cap). Each declared volume is now a memory-backed folder.

Tested against real Docker on macOS (Docker Desktop 29) and Linux (Debian 12, Docker 20.10),
with tests that fail when each fix is removed.

## Step 1: sending images

### The grant

A new grant term, `images_bytes`: the borrower may send Docker images taking up to this many
bytes on the lender. 0 (the default, and what lenders older than this read) means none, so an
older lender never receives an image. It is shown in the request, named in the approval prompt,
needs presence like every approval, and may only be lowered by the lender (reduce-only).

### What travels

An image is its config (a small JSON whose SHA-256 is the image id) and its layers (tar files;
the config lists each layer's SHA-256 as `rootfs.diff_ids`). Layers travel **uncompressed**, as
ordinary content-addressed blobs under the grant (threat model I14), so each blob's digest *is*
the layer's diff id and the lender verifies everything by hashing alone.

1. The borrower reads the image's id, layers and platform (`docker image inspect`).
2. It asks the lender which layers it needs (`ImageQuery`). The lender answers: "have it"
   (already loaded for this borrower), "send layers from *k* on", or a refusal (no image
   allowance, wrong processor or OS, too large).
3. Only then does the borrower export the image (`docker save`), decompress what it needs, check
   each layer against the config, and upload the missing blobs as it uploads files.
4. The task names the image by id; the lender loads it (below) and runs it exactly as it runs
   any image: no network, unprivileged user, read-only system, hard caps.

A rebuild that changes only the top layer sends only that layer: measured on both Docker
versions here, `docker load` accepts an archive that leaves out layers Docker already has (in
the same order beneath), and refuses cleanly ("no such file") when it does not have them.

### On the lender

- **Checks before loading**: the config's digest is the image id; its `rootfs.diff_ids` are the
  layers, in order; its OS and processor are the lender's Docker's; the total fits the grant's
  allowance (older images of the same borrower are removed first, least recently used, if they
  are not in use).
- **Never the borrower's names**: tested, `docker load` silently re-points a tag the lender
  already has. The lender writes the archive's manifest itself, tagged
  `gimmecores.local/from-<borrower>:<id>`; it never passes on names from the borrower.
- **Only this borrower**: a sent image is listed as that borrower's; another borrower naming it
  (by tag or id) is told it is not on the lender.
- **Disk**: the received layers are deleted once loaded (Docker keeps the only copy). The
  allowance counts the borrower's loaded images; the grant's disk limit counts the blobs while
  they wait.
- **Removed** when the borrower's last grant ends (with its other blobs): only the tags
  GimmeCores added, so an image the owner also has under a name of their own stays.
- **Audited** on both sides: image id, size, layers received.

### Not yet

- Compressed transfer (zstd) for slow Wi-Fi.
- Docker's newer containerd image store: `docker save` there gives compressed layers (the
  borrower decompresses them; supported), and whether `docker load` there accepts archives
  without the layers it has is not tested yet (until it is, a lender on that store is sent
  every layer).
- Windows lenders (lending is not available on Windows yet).
