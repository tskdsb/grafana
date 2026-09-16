#!/bin/bash
# Build & push a docker image from the current checkout, for the 9.5.18 line.
#
# Unlike the ark script this is derived from, this one builds WHAT IS CHECKED
# OUT. The ark version resolves the newest v*-ark-* tag and checks it out; on
# this line that silently produces a 12.4.5 image with none of the branch under
# test in it, which is exactly the failure this script exists to avoid.
#
# Typical usage on the build server:
#   git checkout feat/my-branch
#   bash scripts/bytedance/build-image.sh
#
# The tag is derived from the branch and the short SHA, so two builds of
# different commits never collide and an image can always be traced back:
#   maas-boe-cn-beijing.cr.volces.com/maas/grafana:v9.5.18-<branch>-<sha>
#
# Knobs:
#   TAG=<full tag>   Override the computed tag (image name stays $REGISTRY:$TAG).
#   REGISTRY=...     Override the image registry.
#   ALLOW_DIRTY=1    Build with uncommitted changes (tag gets a -dirty suffix).
#   SKIP_PUSH=1      Build only, do not push.

set -e

REGISTRY="${REGISTRY:-maas-boe-cn-beijing.cr.volces.com/maas/grafana}"

# The tree must be clean, or the image cannot be traced back to a commit: the
# SHA in the tag would name a commit that is not what was built. --allow-dirty
# exists for iterating, and marks the tag so such an image is never mistaken
# for a reproducible one.
DIRTY=""
if ! git diff --quiet || ! git diff --cached --quiet; then
  if [ "${ALLOW_DIRTY:-}" = "1" ]; then
    DIRTY="-dirty"
    echo "==> WARNING: building a dirty tree (ALLOW_DIRTY=1); tagging $DIRTY"
  else
    echo "ERR: working tree not clean. Commit first, or set ALLOW_DIRTY=1" >&2
    git status --short >&2
    exit 1
  fi
fi

BRANCH=$(git rev-parse --abbrev-ref HEAD)
SHA=$(git rev-parse --short=11 HEAD)
VERSION=$(sed -n 's/.*"version": "\([^"]*\)".*/\1/p' package.json | head -1)

if [ -n "${TAG:-}" ]; then
  IMAGE_TAG="$TAG"
else
  # Slashes are legal in a branch name and illegal in a docker tag.
  SAFE_BRANCH=$(echo "$BRANCH" | tr '/' '-')
  IMAGE_TAG="v${VERSION}-${SAFE_BRANCH}-${SHA}${DIRTY}"
fi
IMAGE="${REGISTRY}:${IMAGE_TAG}"

echo "==> Branch:  $BRANCH"
echo "==> Commit:  $(git rev-parse HEAD)"
echo "==> Version: $VERSION"
echo "==> Image:   $IMAGE"

set -x
make build-docker-full DOCKER_BUILD_ARGS="--tag ${IMAGE}"
{ set +x; } 2>/dev/null

if [ "${SKIP_PUSH:-}" = "1" ]; then
  echo "==> SKIP_PUSH=1, not pushing"
else
  set -x
  docker push "${IMAGE}"
  { set +x; } 2>/dev/null
fi

echo ""
echo "=============================="
echo "  Image: ${IMAGE}"
echo "=============================="
