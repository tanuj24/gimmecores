# Container images: running the borrower's own image on the lender

Status: **built** (2026-11-15): step 0 (safety fixes to the container runner) and step 1
(sending images). Tested against Docker Desktop 29 (macOS), Docker 29 on Debian 12 (both image
stores) and Debian 12's own Docker 20.10.

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

An image is its config (a small JSON document) and its layers (tar files; the config lists each
layer's SHA-256 as `rootfs.diff_ids`). Layers travel **uncompressed**, as ordinary
content-addressed blobs under the grant (threat model I14), so each blob's digest *is* the
layer's diff id and the lender verifies everything by hashing alone. The lender identifies an
image by its config's SHA-256. Docker's own id for an image differs between its two image
stores (the config's digest in the classic store; a manifest's in the containerd store, Docker
29's default for new installs), so each side keeps what its own Docker calls it: the borrower
names an image by its Docker's id when asking again, and the lender records its Docker's id for
the image it loaded.

1. The borrower reads the image's id, layers and platform (`docker image inspect`).
2. It asks the lender which layers it needs (`ImageQuery`). The lender answers: "have it"
   (already loaded for this borrower), "send layers from *k* on", or a refusal (no image
   allowance, wrong processor or OS, too large).
3. Only then does the borrower export the image (`docker save --platform`, only this computer's
   variant), decompress what it needs (the containerd store keeps layers gzipped), check each
   layer against the config, and upload the missing blobs as it uploads files. One image is
   sent to a lender at a time, so tasks starting together with a new image send it once.
4. The task names the image; the lender loads it (below) and runs it exactly as it runs any
   image: no network, unprivileged user, read-only system, hard caps.

**The archive** the lender writes for `docker load` has both layouts Docker reads: OCI
(`index.json`, read by the containerd store) and the classic `manifest.json`. Both name only
the lender's tag. It holds the config, a manifest the lender writes (giving every layer's
size), and each layer it was sent, once. Measured on Docker 29 with both stores and on Docker
Desktop 29: `docker load` accepts an archive that leaves out layers Docker already has from an
earlier load of ours, and refuses cleanly when it does not have them. The classic store reuses
a layer only with the same layers beneath it (so an image listing an empty layer twice still
needs it sent again, above); the containerd store finds it by digest.

### On the lender

- **Checks before loading**: the config is the one sent (its blob's digest), and lists the
  layers sent among its own; its OS and processor are the lender's Docker's; every layer above
  those Docker already has for this borrower was sent. After loading: the tag names an image
  with exactly those layers, whose id is the config's or the lender's manifest's digest.
- **Never the borrower's names**: tested, `docker load` silently re-points a tag the lender
  already has. The lender writes the archive's manifests itself, tagged
  `gimmecores.local/<lender's key>/from-<borrower's key>:<config's digest>` (whole, so no two images can be
  made to share a tag); it never passes on names from the borrower.
- **Only this borrower**: a sent image is listed as that borrower's; another borrower naming it
  (by tag, id or short id) is told it is not on the lender; names under `gimmecores.local/` are
  refused to every task.
- **Within the allowance**: what Docker holds for a borrower (each distinct layer once) stays
  within its grant's `images_bytes`. Before a load, its least recently used images not in use
  are removed; one sharing the new image's lower layers can only go once the new one is loaded
  (Docker would remove the shared layers with it), so for that moment Docker holds both. If even
  that is not enough (the rest are in use), the task is refused.
- **Disk**: the received layers are deleted once loaded (Docker keeps the only copy). While they
  wait, they count against the grant's disk limit plus what its image allowance has left.
- **Removed** when the borrower's last grant ends (with its other blobs): only the tags
  GimmeCores added, so an image the owner also has under a name of their own stays. A removal
  that could not happen (Docker away, a task still in the image) is retried every 2 s (not
  tested with Docker away). Docker's own list of this lender's tags is swept too, on start and
  every minute, so a tag whose record was lost (an unreadable `images.json`, a stop between a
  load and its record) goes the same way; tags carry the lender's key, so services sharing one
  Docker never sweep each other's. An image is forgotten only when Docker says it is gone, never
  because it did not answer.
- **A task stopped before Docker started it** leaves no container behind holding the image
  (`--rm` only removes containers that ran, so the stop removes it by name).
- **A revoke stops a load**: `docker load` is stopped with the task (not tested yet).
- **Audited** on both sides: image, its config's digest, layers received.

### Using it

```console
$ gmc grants request Desktop --runtime container --cpus 6 --memory 12g --images 8g
$ docker build -t myjob:1 .        # for the lender's processor: --platform linux/arm64 or amd64
$ gmc run --peer Desktop --image myjob:1 --out results -- python train.py
```

`gmc.Pool(image="myjob:1")` does the same, and so do AI agents through `gmc mcp` (the owner's
choice, 2026-11-15): an agent can make this computer send any image on its Docker, under a grant
whose image allowance the owner asked for and the lender approved; it cannot ask for or approve
one itself. Images are not scanned for secrets the way project files are. Without an allowance,
or when this computer's Docker does not have the image, a task only names it, as before.
(`InlineTask.name_image_only` lets a client only name images, should that be wanted.)

### Tests

- `tests/images_sent.rs`, two real services on this machine's one Docker: the first run sends
  the whole image and the lender loads it under its own name; a rebuild sends only its new layer
  (under 256 KB); a third run sends nothing; revoking removes the lender's names and leaves the
  borrower's own images. Four tasks starting together with a new image send it once. A tag of
  the lender's with no record, for a device with no grant, is removed after a restart. An image
  for the other processor is refused before anything is sent; one larger than the allowance
  too; a newer image replaces an older one to stay within it. Another borrower naming the image
  by the lender's tag, its id or a short id is told it is not there. A lender restarted after
  the grant ended removes the images. With one Docker the lender's Docker already has the
  borrower's layers, so these tests cannot tell whether an archive may leave layers out.
- `scripts/linux/e2e-images.sh`, in the Debian test VM, with real `gmc`/`gmcd` and **two
  separate Dockers** (the borrower's with its own containerd): the request's text, the first
  send (every layer), a rebuild (1 of 3 layers), nothing on a third run, an image listing an
  empty layer twice (also beneath what the lender has), removal on revoke. Passes on Docker 29
  with the containerd store and with the classic store (`GMC_E2E_STORE=classic`), and on
  Debian 12's Docker 20.10.
- Breaking each part fails a test: the layer reuse, the check for other borrowers, the
  allowance, and writing a repeated layer only where it first appears (the classic store
  refuses the load; a unit test checks the archive).

### Not yet

- Compressed transfer (zstd) for slow Wi-Fi: layers travel uncompressed, at the link's speed.
- Images are not scanned for secrets the way files are: the borrower names the image itself,
  and a secret built into it goes with it.
- An image the owner already has (the same id) is still sent: sending it is the borrower's
  proof that it has the image.
- Free space in Docker is not checked first; a full disk fails the load with Docker's message.
- Two physical machines (a Mac borrower and a Linux or Mac lender) are not tested yet; the
  two-Docker test runs in one VM.
- Windows lenders (lending is not available on Windows yet).
