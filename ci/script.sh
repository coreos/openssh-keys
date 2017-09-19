# This script takes care of testing your crate

set -ex

cross build --target $TARGET
cross build --target $TARGET --release

if [ ! -z $DISABLE_TESTS ]; then
    exit 0
fi

cross test --target $TARGET
cross test --target $TARGET --release
