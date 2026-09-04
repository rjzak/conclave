#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
#
# Build macOS .app bundles for the Conclave client, server and tracker.
#
# Each crate keeps its bundle metadata in crates/<crate>/macos/Info.plist; this
# script builds the binary, lays out the bundle around it, stamps the version
# from Cargo.toml, and ad-hoc signs the result. Signing matters even for local
# use: Launch Services is more reliable about registering the client's
# "conclave://" URL scheme for a signed bundle.
#
#   macos/bundle.sh                          # all three, native arch
#   macos/bundle.sh client                   # just the client
#   macos/bundle.sh -t aarch64-apple-darwin -t x86_64-apple-darwin
#                                            # universal (lipo'd) bundles

set -eu

usage() {
	cat <<'EOF'
Usage: macos/bundle.sh [options] [client|server|tracker ...]

With no crate named, all three are bundled.

Options:
  -o, --out DIR        Output directory for the .app bundles
                       (default: $CARGO_TARGET_DIR/macos, i.e. target/macos)
  -t, --target TRIPLE  Rust target triple to build. Pass twice to produce a
                       universal binary via lipo. Default: the host target.
      --no-build       Use binaries that are already built
  -s, --sign IDENTITY  codesign identity (default: "-", ad-hoc)
                       Find signing identities by running:
                       `security find-identity -v -p codesigning`
      --no-sign        Skip code signing entirely
  -h, --help           Show this message
EOF
}

repo_root=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
target_dir=${CARGO_TARGET_DIR:-"$repo_root/target"}
out_dir=""
targets=""
build=1
sign_identity="-"

while [ $# -gt 0 ]; do
	case "$1" in
	-o | --out)
		out_dir=$2
		shift 2
		;;
	-t | --target)
		targets="$targets $2"
		shift 2
		;;
	--no-build)
		build=0
		shift
		;;
	-s | --sign)
		sign_identity=$2
		shift 2
		;;
	--no-sign)
		sign_identity=""
		shift
		;;
	-h | --help)
		usage
		exit 0
		;;
	-*)
		echo "bundle.sh: unknown option $1" >&2
		usage >&2
		exit 2
		;;
	*)
		break
		;;
	esac
done

crates=${*:-"client server tracker"}
: "${out_dir:=$target_dir/macos}"

case "$(uname -s)" in
Darwin) ;;
*)
	echo "bundle.sh: macOS bundles can only be built on macOS" >&2
	exit 1
	;;
esac

plist_buddy=/usr/libexec/PlistBuddy

# Version for CFBundleShortVersionString/CFBundleVersion. Every crate inherits
# version.workspace, so the workspace manifest is the single source of truth.
version=$(sed -n '/^\[workspace\.package\]/,/^\[/ s/^version *= *"\([^"]*\)".*/\1/p' "$repo_root/Cargo.toml")
[ -n "$version" ] || {
	echo "bundle.sh: could not read version from Cargo.toml" >&2
	exit 1
}

# Only the server and tracker gate their GUI behind a feature; the client is
# always graphical.
features_for() {
	case "$1" in
	server | tracker) echo "--features=gui" ;;
	*) echo "" ;;
	esac
}

# Where cargo drops the binary for a given target triple ("" = host).
binary_path() {
	if [ -n "$1" ]; then
		echo "$target_dir/$1/release/$2"
	else
		echo "$target_dir/release/$2"
	fi
}

mkdir -p "$out_dir"

for crate in $crates; do
	src_plist="$repo_root/crates/$crate/macos/Info.plist"
	[ -f "$src_plist" ] || {
		echo "bundle.sh: no macOS bundle metadata at $src_plist" >&2
		exit 1
	}

	package="conclave-$crate"
	executable=$("$plist_buddy" -c "Print :CFBundleExecutable" "$src_plist")
	app_name=$("$plist_buddy" -c "Print :CFBundleName" "$src_plist")
	app="$out_dir/$app_name.app"
	features=$(features_for "$crate")

	if [ "$build" -eq 1 ]; then
		if [ -n "$targets" ]; then
			for triple in $targets; do
				# shellcheck disable=SC2086
				(cd "$repo_root" && cargo build -p "$package" --release \
					--target="$triple" $features)
			done
		else
			# shellcheck disable=SC2086
			(cd "$repo_root" && cargo build -p "$package" --release $features)
		fi
	fi

	rm -rf "$app"
	mkdir -p "$app/Contents/MacOS" "$app/Contents/Resources"

	# A universal binary when several targets were given, otherwise a copy.
	if [ -n "$targets" ]; then
		inputs=""
		for triple in $targets; do
			path=$(binary_path "$triple" "$executable")
			[ -f "$path" ] || {
				echo "bundle.sh: missing $path (build it, or drop --no-build)" >&2
				exit 1
			}
			inputs="$inputs $path"
		done
		# shellcheck disable=SC2086
		lipo -create -output "$app/Contents/MacOS/$executable" $inputs
	else
		path=$(binary_path "" "$executable")
		[ -f "$path" ] || {
			echo "bundle.sh: missing $path (build it, or drop --no-build)" >&2
			exit 1
		}
		cp "$path" "$app/Contents/MacOS/$executable"
	fi
	chmod 755 "$app/Contents/MacOS/$executable"

	cp "$src_plist" "$app/Contents/Info.plist"
	"$plist_buddy" -c "Set :CFBundleShortVersionString $version" "$app/Contents/Info.plist" >/dev/null
	"$plist_buddy" -c "Set :CFBundleVersion $version" "$app/Contents/Info.plist" >/dev/null

	# CFBundlePackageType + CFBundleSignature, in the form Finder expects.
	printf 'APPL????' >"$app/Contents/PkgInfo"

	# The icon is optional: the bundle is valid without one, macOS just shows
	# the generic application icon.
	icon=$("$plist_buddy" -c "Print :CFBundleIconFile" "$app/Contents/Info.plist" 2>/dev/null || true)
	if [ -n "$icon" ] && [ -f "$repo_root/crates/$crate/macos/$icon" ]; then
		cp "$repo_root/crates/$crate/macos/$icon" "$app/Contents/Resources/$icon"
	elif [ -n "$icon" ]; then
		"$plist_buddy" -c "Delete :CFBundleIconFile" "$app/Contents/Info.plist" >/dev/null
	fi

	plutil -lint "$app/Contents/Info.plist" >/dev/null

	if [ -n "$sign_identity" ]; then
		codesign --force --sign "$sign_identity" --timestamp=none "$app"
	fi

	echo "Created: $app"
done
