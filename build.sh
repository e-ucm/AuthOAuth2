#!/usr/bin/env bash
set -eo pipefail
[[ "${DEBUG}" == "true" ]] && set -x

: ${BUILD_VERSION:=1.5.0}

SOURCE=${BASH_SOURCE[0]}
while [ -L "$SOURCE" ]; do # resolve $SOURCE until the file is no longer a symlink
  SCRIPT_DIR=$( cd -P "$( dirname "$SOURCE" )" >/dev/null 2>&1 && pwd )
  SOURCE=$(readlink "$SOURCE")
  [[ $SOURCE != /* ]] && SOURCE=$SCRIPT_DIR/$SOURCE # if $SOURCE was a relative symlink, we need to resolve it relative to the path where the symlink file was located
done
SCRIPT_DIR=$( cd -P "$( dirname "$SOURCE" )" >/dev/null 2>&1 && pwd )

function usage ()
{
    echo 1>&2 "Usage: ${SOURCE} [Options]"
    echo 1>&2 "Build limesurvey AuthOAuth2 plugin as a release (${BUILD_VERSION})."
    echo 1>&2 "Options:"
    echo 1>&2 "  -h, --help"
    echo 1>&2 "      Shows this help message and exits."
    echo 1>&2 "  -b, --build <build version>"
    echo 1>&2 "      Build version to compile the extension."
}

LIST_LONG_OPTIONS=(
  "help"
  "build:"
)
LIST_SHORT_OPTIONS=(
  "h"
  "b:"
)

opts=$(getopt \
    --longoptions "$(printf "%s," "${LIST_LONG_OPTIONS[@]}")" \
    --options "$(printf "%s", "${LIST_SHORT_OPTIONS[@]}")" \
    --name "${SOURCE}" \
    -- "$@"
)

eval set -- $opts

while [[ $# -gt 0 ]]; do
  case "$1" in
    -b | --build )
        BUILD_VERSION="$2"
        shift 2
        ;;
    --)
      shift
      break
      ;;
    *)
      usage
      exit 1
      ;;
    esac
done

echo $SCRIPT_DIR
PLUGIN_NAME=$(basename $SCRIPT_DIR);

if [[ -d "$SCRIPT_DIR/builds-$BUILD_VERSION" ]]; then 
  rm -rf "$SCRIPT_DIR/builds-$BUILD_VERSION"
fi
mkdir "$SCRIPT_DIR/builds-$BUILD_VERSION"

pushd "$SCRIPT_DIR"
composer install
zip -r $SCRIPT_DIR/builds-$BUILD_VERSION/$PLUGIN_NAME-$BUILD_VERSION.zip ./ -x "*.git*" "*build.sh*" "*builds-*" "*docs*" "*.md*"
popd

pushd "$SCRIPT_DIR/builds-$BUILD_VERSION"
sha256sum ./* > "$SCRIPT_DIR/builds-$BUILD_VERSION/SHA256SUMS"
popd

# Success message
echo "Plugin '$PLUGIN_NAME' has been packaged into '$SCRIPT_DIR/builds-$BUILD_VERSION/$PLUGIN_NAME-$BUILD_VERSION.zip'."