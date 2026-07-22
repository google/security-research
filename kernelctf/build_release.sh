#!/bin/bash
set -ex

usage() {
    echo "Usage: $0 (lts|lts2|cos|mitigation)-<version> [<branch-tag-or-commit>]";
    exit 1;
}

RELEASE_NAME="$1"
BRANCH="$2"

if [[ ! "$RELEASE_NAME" =~ ^(lts|lts2|cos|mitigation)-(.*) ]]; then usage; fi
TARGET="${BASH_REMATCH[1]}"
VERSION="${BASH_REMATCH[2]}"

case $TARGET in
  lts | lts2)
    REPO="https://github.com/gregkh/linux"
    DEFAULT_BRANCH="v${VERSION}"
    case $VERSION in
        6.12.*) CONFIG_FN="${TARGET}-6.12.config" ;;
        6.6.*) CONFIG_FN="${TARGET}-6.6.config" ;;
        6.1.*) CONFIG_FN="${TARGET}-6.1.config" ;;
    esac
    if [ -z "$CONFIG_FN" ]; then echo "Failed to select config (VERSION=$VERSION)"; exit 1; fi
    if [ "$TARGET" == "lts2" ]; then
        export LLVM=1
        export LOCALVERSION=""
    fi
    ;;
  cos)
    REPO="https://cos.googlesource.com/third_party/kernel"
    ;;
  mitigation)
    REPO="https://github.com/thejh/linux"
    case $VERSION in
        v4*)
            case $VERSION in
                v4-6.6*) DEFAULT_BRANCH="slub-virtual-v6.6" ;;
                v4-6.12*) DEFAULT_BRANCH="mitigations-next" ;;
            esac
            CONFIG_FN="mitigation-v4.config"
            ;;
        v3-* | v3b-*)
            DEFAULT_BRANCH="mitigations-next"
            case $VERSION in
                v3-6.1.55) CONFIG_FN="mitigation-v3.config" ;;
                v3b-6.1.55) CONFIG_FN="mitigation-v3b.config" ;;
            esac
            CONFIG_FULL_FN="mitigation-v3-full.config"
            ;;
        6.1 | 6.1-v2)
            DEFAULT_BRANCH="slub-virtual-v6.1"
            CONFIG_FN="mitigation-v1.config"
            ;;
    esac ;;
  *)
    usage ;;
esac

BRANCH="${BRANCH:-$DEFAULT_BRANCH}"
if [ -z "$BRANCH" ]; then usage; fi

echo "REPO=$REPO"
echo "BRANCH=$BRANCH"
echo "CONFIG_FN=$CONFIG_FN"

BASEDIR=`pwd`
BUILD_DIR="$BASEDIR/builds/$RELEASE_NAME"
RELEASE_DIR="$BASEDIR/releases/$RELEASE_NAME"
CONFIGS_DIR="$BASEDIR/kernel_configs"

if [ -d "$RELEASE_DIR" ]; then echo "Release directory already exists. Stopping."; exit 1; fi

echo "GCC version"
echo "================="
gcc --version || true
echo

echo "Clang version"
echo "================="
clang --version || true
echo "================="
echo

mkdir -p $BUILD_DIR 2>/dev/null || true
cd $BUILD_DIR
if [ ! -d ".git" ]; then git init && git remote add origin $REPO; fi

if ! git checkout $BRANCH; then
    git fetch --depth 1 origin $BRANCH:$BRANCH || true # TODO: hack, solve it better
    git checkout $BRANCH
fi

# not necessary for the build itself, but it can be useful for comparing the config changes
if [ "$TARGET" == "lts" ]; then
    make defconfig
    mv .config upstream_defconfig
fi

if [ "$TARGET" == "cos" ]; then
    rm lakitu_defconfig || true
    make lakitu_defconfig
    cp .config lakitu_defconfig
elif [ "$TARGET" != "lts2" ]; then
    if [[ $VERSION == "6.12"* ]]; then
        curl 'https://cos.googlesource.com/third_party/kernel/+/refs/heads/cos-6.12/arch/x86/configs/lakitu_defconfig?format=text'|base64 -d > lakitu_defconfig
    else
        curl 'https://cos.googlesource.com/third_party/kernel/+/refs/heads/cos-6.1/arch/x86/configs/lakitu_defconfig?format=text'|base64 -d > lakitu_defconfig
    fi
    cp lakitu_defconfig .config
fi

if [ "$TARGET" != "lts2" ]; then
    # build everything into the kernel instead of modules
    # note: this can increase the attack surface!
    sed -i s/=m/=y/g .config
fi

if [ ! -z "$CONFIG_FN" ]; then
    cp $CONFIGS_DIR/$CONFIG_FN kernel/configs/
    make $CONFIG_FN
fi

make olddefconfig

if [ "$TARGET" != "lts2" ] && [ ! -z "$CONFIG_FN" ]; then
    if scripts/diffconfig $CONFIGS_DIR/$CONFIG_FN .config|grep "^[^+]"; then
        echo "Config did not apply cleanly."
        exit 1
    fi
fi

if [ ! -z "$CONFIG_FULL_FN" ]; then
    if scripts/diffconfig $CONFIGS_DIR/$CONFIG_FULL_FN .config|grep "^[^+]"; then
        echo "The full config has differences compared to the applied config. Check if the base config changed since custom config was created."
        exit 1
    fi
fi

# since cos-109-17800-218-14, COS does not build due to __cold redefinition, quickfix this until its fixed in the COS repo
if [ "$TARGET" == "cos" ] && grep __cold include/linux/compiler_types.h; then
    sed -i 's/.*#define.__cold.*//' include/linux/compiler_attributes.h
fi

install_and_tar_module_type() {
    local DEST_DIR="$1"
    local KRELEASE="$2"
    local MOD_TYPE="$3"
    local STRIP="$4"
    local WORK_DIR="$BUILD_DIR/$MOD_TYPE"

    echo "--> Generating ${MOD_TYPE} modules..."
    rm -rf "$WORK_DIR"
    mkdir -p "$WORK_DIR"

    local MAKE_ARGS=(modules_install INSTALL_MOD_PATH="$WORK_DIR" KERNELRELEASE="$KRELEASE")
    if [ -n "$STRIP" ]; then
        MAKE_ARGS+=(INSTALL_MOD_STRIP="$STRIP")
    fi

    make "${MAKE_ARGS[@]}"
    rm -f "$WORK_DIR/lib/modules/$KRELEASE/build" "$WORK_DIR/lib/modules/$KRELEASE/source"
    tar -czf "$DEST_DIR/${MOD_TYPE}.tar.gz" -C "$WORK_DIR" lib
}

install_and_tar_modules() {
    local DEST_DIR="$1"
    local KRELEASE="$2"

    install_and_tar_module_type "$DEST_DIR" "$KRELEASE" "modules" "1"
    install_and_tar_module_type "$DEST_DIR" "$KRELEASE" "modules_dbgsym" ""
}

build_and_package() {
    local REL_NAME="$1"
    local REL_DIR="$2"
    shift 2
    local CFG_FILES=("$@")

    for cfg in "${CFG_FILES[@]}"; do
        echo "--> Checking required config: $(basename "$cfg")..."
        python3 "$BASEDIR/check_required_config.py" .config "$cfg"
    done

    make olddefconfig
    make -j`nproc`

    mkdir -p "$REL_DIR" 2>/dev/null || true

    echo "REPOSITORY_URL=$REPO" > "$REL_DIR/COMMIT_INFO"
    (echo -n "COMMIT_HASH="; git rev-parse HEAD) >> "$REL_DIR/COMMIT_INFO"

    cp "$BUILD_DIR/arch/x86/boot/bzImage" "$REL_DIR/"
    if [ -f "$BUILD_DIR/lakitu_defconfig" ]; then cp "$BUILD_DIR/lakitu_defconfig" "$REL_DIR/"; fi
    if [ -f "$BUILD_DIR/upstream_defconfig" ]; then cp "$BUILD_DIR/upstream_defconfig" "$REL_DIR/"; fi
    cp "$BUILD_DIR/.config" "$REL_DIR/"
    gzip -c "$BUILD_DIR/vmlinux" > "$REL_DIR/vmlinux.gz"

    if [ "$TARGET" == "lts2" ]; then
        local KERNEL_REL
        KERNEL_REL=$(make -s kernelrelease)
        install_and_tar_modules "$REL_DIR" "$KERNEL_REL"
    fi
}

if [ "$TARGET" == "lts2" ]; then
    build_and_package "$RELEASE_NAME" "$RELEASE_DIR" "$CONFIGS_DIR/lts2-required.config"

    MITIGATION_RELEASE_NAME="${RELEASE_NAME}_mitigation"
    MITIGATION_RELEASE_DIR="$BASEDIR/releases/$MITIGATION_RELEASE_NAME"

    echo "=========================================================="
    echo "  Building LTS2 Mitigation Release ($MITIGATION_RELEASE_NAME)"
    echo "=========================================================="

    if [ -d "$MITIGATION_RELEASE_DIR" ]; then
        echo "Mitigation release directory already exists ($MITIGATION_RELEASE_DIR). Stopping."
        exit 1
    fi

    mkdir -p kernel/configs
    cp "$CONFIGS_DIR/lts2-mitigation.config" kernel/configs/mitigation.config
    make mitigation.config

    build_and_package "$MITIGATION_RELEASE_NAME" "$MITIGATION_RELEASE_DIR" "$CONFIGS_DIR/lts2-required.config" "$CONFIGS_DIR/lts2-mitigation.config"
else
    build_and_package "$RELEASE_NAME" "$RELEASE_DIR"
fi

echo "=========================================================="
echo "  Release build completed successfully!"
echo "  Primary release: $RELEASE_DIR"
if [ "$TARGET" == "lts2" ]; then
    echo "  Mitigation release: $MITIGATION_RELEASE_DIR"
fi
echo "=========================================================="
