#!/bin/bash
# Frida Injection Script
set -eo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
NC='\033[0m'

SIGN_ONLY=0
USE_FRIDA=0

die() {
    echo -e "${RED}[ERROR] $1${NC}" >&2
    exit 1
}

warn() {
    echo -e "${YELLOW}[WARNING] $1${NC}" >&2
}

check_deps() {
    command -v codesign >/dev/null || die "Missing Xcode command line tools, try: xcode-select --install"
    command -v security >/dev/null || die "Missing security command, your device may be incomplete"
    command -v plutil >/dev/null || die "Missing plutil command, your device may be incomplete"
    command -v pymobiledevice3 >/dev/null || die "pymobiledevice3 not installed, try: python3 -m pip install -U pymobiledevice3"
    command -v insert_dylib >/dev/null || die "insert_dylib not installed, try: git clone https://github.com/Tyilo/insert_dylib && cd insert_dylib && xcodebuild && cp build/Release/insert_dylib /usr/local/bin/insert_dylib"
    command -v applesign >/dev/null || die "applesign not installed, try: brew install node && npm install -g applesign"
    command -v ditto >/dev/null || die "Missing ditto, which is usually included with macOS"
    
    if ! command -v openssl >/dev/null; then
        echo -e "${YELLOW}Warning: Missing openssl, will use random strings as fallback. Suggested install: brew install openssl${NC}"
        USE_OPENSSL=0
    else
        USE_OPENSSL=1
    fi
    
    if ! command -v pymobiledevice3 >/dev/null; then
        echo -e "${YELLOW}Warning: Missing pymobiledevice3, won't be able to install to device. For this feature please install: python3 -m pip install -U pymobiledevice3${NC}"
        CAN_INSTALL=0
    else
        CAN_INSTALL=1
    fi
}

clean_signatures() {
    echo -e "${YELLOW}Cleaning old signatures...${NC}"
    find "$APP_DIR" -name "_CodeSignature" -type d -exec rm -rf {} +
}

validate_plist() {
    local plist=$1
    if ! plutil -lint "$plist" >/dev/null; then
        die "Invalid plist file: $plist"
    fi
}

extract_bundle_id() {
    local provision_file=$1
    security cms -D -i "$provision_file" -o provision.plist
    validate_plist provision.plist
    
    local app_id
    app_id=$(/usr/libexec/PlistBuddy -c "Print :Entitlements:application-identifier" provision.plist)
    PROV_BUNDLE_ID="${app_id#*.}"
    
    if [[ $app_id == *"*"* ]]; then
        echo -e "${YELLOW}Warning: Provision file uses wildcard Bundle ID ($app_id), manual specification may be required${NC}"
    fi
    
    echo -e "${GREEN}Extracted Bundle ID from provision: ${YELLOW}$PROV_BUNDLE_ID${NC}"
}

select_identity() {
    local identities=()
    while IFS= read -r line; do
        identities+=("$line")
    done < <(security find-identity -p codesigning -v | grep -oE '".*"' | tr -d '"')

    [ ${#identities[@]} -gt 0 ] || die "No valid signing certificates found"
    
    PS3="Please select a signing certificate (enter number): "
    select name in "${identities[@]}"; do
        [ -n "$name" ] && break
    done
    SIGN_IDENTITY="$name"
}

prepare_provision() {
    [ -f "$1" ] || die "Provision file not found: $1"
    security cms -D -i "$1" > provision.plist
    plutil -lint provision.plist >/dev/null || die "Invalid provision file"
    
    # Extract Bundle ID
    local app_id
    app_id=$(/usr/libexec/PlistBuddy -c "Print :Entitlements:application-identifier" provision.plist)
    PROV_BUNDLE_ID="${app_id#*.}"
    
    # Extract and save entitlements
    echo -e "${YELLOW}Extracting signing entitlements...${NC}"
    /usr/libexec/PlistBuddy -x -c "Print :Entitlements" provision.plist > entitlements.plist
    validate_plist entitlements.plist || die "Failed to extract signing entitlements"
    
    cp "$1" "$APP_DIR/embedded.mobileprovision"
    echo -e "${GREEN}Using provision file: $(basename "$1")${NC}"
}

generate_gadget_config() {
    local dylib_name="$1"
    local config_path="$APP_DIR/${dylib_name%.*}.config"
    
    cat > "$config_path" <<EOF
{
  "interaction": {
    "type": "listen",
    "address": "0.0.0.0",
    "port": 27042,
    "on_port_conflict": "fail",
    "on_load": "wait"
  }
}
EOF
    echo -e "${GREEN}Generated config file: $(basename "$config_path")${NC}"
}

verify_injection() {
    local binary=$1
    local dylib=$2
    
    # Check LC_LOAD_
    echo -e "${YELLOW}Verifying dylib load commands...${NC}"
    if ! otool -l "$binary" | grep -A4 LC_LOAD_ | grep -q "$dylib"; then
        echo -e "${RED}Dylib $dylib was not successfully injected${NC}"
        die "Dylib injection failed"
    fi
    echo -e "${GREEN}Dylib load commands verification passed${NC}"
    
    # Check path correction
    local dylib_path="$APP_DIR/Frameworks/$DYLIB_NAME"
    echo -e "${YELLOW}Checking dylib ID...${NC}"
    
    # Use otool -D to check dylib ID
    local install_name
    install_name=$(otool -D "$dylib_path" | tail -n 1)
    
    if [[ "$install_name" != "@executable_path/Frameworks/$DYLIB_NAME" ]]; then
        echo -e "${RED}Incorrect dylib ID: $install_name${NC}"
        die "Dylib ID correction failed"
    fi
}

install_ipa() {
    if [ $CAN_INSTALL -eq 1 ]; then
        pymobiledevice3 apps install "$OUTPUT_IPA"
    else
        warn "Can't install to device, pymobiledevice3 is missing"
    fi
}

show_usage() {
    cat <<EOF
Usage:
    $(basename "$0") [options] <ipa_file> [provision_file]

Parameters:
    ipa_file      - Required, path to the IPA file to be injected
    provision_file - Optional, provision file for re-signing, defaults to embedded.mobileprovision

Options:
    -s, --sign-only    Only sign and install the IPA without injecting dylibs

Examples:
    $(basename "$0") WeChat.ipa
    $(basename "$0") WeChat.ipa profile.mobileprovision
    $(basename "$0") --sign-only WeChat.ipa profile.mobileprovision
EOF
    exit 1
}

get_real_bundle_id() {
    local target_plist="$APP_DIR/Info.plist"
    REAL_BUNDLE_ID=$(/usr/libexec/PlistBuddy -c "Print :CFBundleIdentifier" "$target_plist")
}

sign_dylibs() {
    # Following objection's implementation logic, sign all dylibs in the app
    local app_folder="$1"

    while IFS= read -r -d $'\0' file; do
        if [[ "$file" == *.dylib ]]; then
        echo -e "${YELLOW}Signing dylib: ${file#"$app_folder"/}${NC}"
            codesign -f -v -s "$SIGN_IDENTITY" "$file"
        fi
    done < <(find "$app_folder" -type f -print0)
}

[ $# -eq 0 ] && show_usage

while [[ $# -gt 0 ]]; do
    case $1 in
        -s|--sign-only)
            SIGN_ONLY=1
            echo -e "${GREEN}Running in sign-only mode (no dylib injection)${NC}"
            shift
            ;;
        *)
            break
            ;;
    esac
done

[ $# -eq 0 ] && show_usage

# Prepare working directory
WORK_DIR="work"
rm -rf "$WORK_DIR"
mkdir -p "$WORK_DIR"


INPUT_IPA="$1"
PROVISION="${2:-embedded.mobileprovision}"
OUTPUT_IPA="${INPUT_IPA%.*}_patched.ipa"


# Check dependencies
check_deps
[ -f "$INPUT_IPA" ] || die "Specified IPA file does not exist"
[ -f "$PROVISION" ] || die "Specified provision file does not exist"

if [ $SIGN_ONLY -eq 0 ]; then
    # Check for dylibs and frameworks in the current directory
    DYLIBS=($(find . -maxdepth 1 -name "*.dylib" -type f 2>/dev/null))
    FRAMEWORKS=($(find . -maxdepth 1 -name "*.framework" -type d 2>/dev/null))

    if [ ${#DYLIBS[@]} -eq 0 ] && [ ${#FRAMEWORKS[@]} -eq 0 ]; then
        die "Error: No dylib files or frameworks found in the current directory"
    fi
fi

# Select signing certificate
select_identity


# Unpack IPA
echo -e "${GREEN}Unpacking IPA...${NC}"
# 使用ditto替换unzip以更好地支持中文文件名
ditto -x -k "$INPUT_IPA" "$WORK_DIR" || die "Failed to extract IPA"
APP_DIR=$(find "$WORK_DIR" -name "*.app" -type d | head -n1)
[ -d "$APP_DIR" ] || die "Could not find .app directory"

# Prepare provision file and extract Bundle ID
prepare_provision "$PROVISION" 
extract_bundle_id "$PROVISION"

INJECTED_DYLIBS=()

if [ $SIGN_ONLY -eq 0 ]; then
    for dylib in "${DYLIBS[@]}"; do

        # Inject dylib
        DYLIB_NAME="lib$(if [ $USE_OPENSSL -eq 1 ]; then openssl rand -hex 6; else head /dev/urandom | tr -dc 'a-f0-9' | head -c 12; fi).dylib"
        mkdir -p "$APP_DIR/Frameworks"
        cp "$dylib" "$APP_DIR/Frameworks/$DYLIB_NAME"
        install_name_tool -id "@executable_path/Frameworks/$DYLIB_NAME" "$APP_DIR/Frameworks/$DYLIB_NAME"

        # Generate config for Frida Gadget
        if [[ "$dylib" == *FridaGadget.dylib ]]; then
            USE_FRIDA=1
            generate_gadget_config "$DYLIB_NAME"
        else
            USE_FRIDA=0
        fi

        # Modify executable file
        BINARY_NAME=$(/usr/libexec/PlistBuddy -c "Print :CFBundleExecutable" "$APP_DIR/Info.plist")
        BINARY_PATH="$APP_DIR/$BINARY_NAME"

        echo -e "${YELLOW}Injecting ${dylib} to ${APP_DIR}/Frameworks/${DYLIB_NAME}...${NC}"
        insert_dylib --strip-codesig --all-yes --inplace "@executable_path/Frameworks/$DYLIB_NAME" "$BINARY_PATH"
        INJECTED_DYLIBS+=("$DYLIB_NAME")

    done

    # Inject all frameworks in the current directory
    for framework in "${FRAMEWORKS[@]}"; do
        FRAMEWORK_NAME=$(basename "$framework")
        mkdir -p "$APP_DIR/Frameworks"
        cp -r "$framework" "$APP_DIR/Frameworks/"

        # Assume dylib name is the same as framework name
        DYLIB_IN_FRAMEWORK="${FRAMEWORK_NAME%.framework}"
        DYLIB_FILE="$APP_DIR/Frameworks/$FRAMEWORK_NAME/$DYLIB_IN_FRAMEWORK"
        if [ ! -f "$DYLIB_FILE" ]; then
            die "Could not find dylib file in framework: $DYLIB_FILE"
        fi

        # Modify install name
        install_name_tool -id "@executable_path/Frameworks/$FRAMEWORK_NAME/$DYLIB_IN_FRAMEWORK" "$DYLIB_FILE"
        DYLIB_PATH="@executable_path/Frameworks/$FRAMEWORK_NAME/$DYLIB_IN_FRAMEWORK"

        echo -e "${YELLOW}Injecting framework ${framework} to ${APP_DIR}/Frameworks/${FRAMEWORK_NAME}...${NC}"
        insert_dylib --strip-codesig --all-yes --inplace "$DYLIB_PATH" "$BINARY_PATH"
        INJECTED_DYLIBS+=("$DYLIB_PATH")
    done

    echo -e "${YELLOW}Verifying injection results...${NC}"

    for dylib in "${INJECTED_DYLIBS[@]}"; do
        verify_injection "$BINARY_PATH" "$dylib"
    done

    echo -e "${GREEN}Dylib ID check passed${NC}"
else
    echo -e "${GREEN}Sign-only mode: Skipping dylib injection...${NC}"
fi

# Clean old signatures
clean_signatures

# Sign all dylibs
if [ $SIGN_ONLY -eq 0 ]; then
    sign_dylibs "$APP_DIR"
fi

cd "$WORK_DIR"
ditto -c -k --sequesterRsrc --keepParent Payload "../tmp.ipa" || die "Failed to create IPA"
cd ..

# Use applesign for re-signing with the extracted Bundle ID
echo -e "${GREEN}Starting re-signing process...${NC}"
applesign --identity "$SIGN_IDENTITY" \
 --mobileprovision "$PROVISION" \
 --bundleid "$PROV_BUNDLE_ID" \
 --clone-entitlements \
 --output "./$OUTPUT_IPA" \
 "./tmp.ipa"

rm -rf ./tmp.ipa
rm entitlements.plist
rm provision.plist
rm -rf ./Payload
rm -rf "$WORK_DIR"

# Save unpacked result for debugging
ditto -x -k "$OUTPUT_IPA" . || die "Failed to extract final IPA"

# Save path to the .app after unpacking
APP_DIR="./Payload/$(basename "$APP_DIR")"

# Get bundle ID for installation
get_real_bundle_id

# Install
echo -e "${GREEN}Installing IPA...${NC}"
install_ipa

echo -e "\n${GREEN}Injection successful!${NC}"
echo -e "${GREEN}--------------------${NC}"
echo -e "${GREEN}Output file: ${YELLOW}$OUTPUT_IPA${NC}"
echo -e "${GREEN}Bundle ID: ${YELLOW}$REAL_BUNDLE_ID${NC}"
if [ "$USE_FRIDA" -eq 1 ]; then
    echo -e "${GREEN}Frida listening address: ${YELLOW}0.0.0.0:27042${NC}"
fi

if [ $CAN_INSTALL -eq 0 ]; then
    exit 0
fi

# Get installation path
APP_PATH=$(pymobiledevice3 apps query "$REAL_BUNDLE_ID" | grep "\"Path\"" | sed -nE 's/.*"Path": "([^"]+).*/\1/p')

echo -e "${GREEN}App path: ${YELLOW}$APP_PATH${NC}"
echo -e "${GREEN}--------------------${NC}"
echo -en "${GREEN}Run 'sudo python3 -m pymobiledevice3 remote tunneld' to open a tunnel, then press ENTER to continue...${NC}"

read -r

# Start debugserver
output=$(pymobiledevice3 developer debugserver start-server 2>&1)
tmp_cmd=$(echo "$output" | grep -E "process connect connect://" | tail -n 2 | head -n 1)
connection_url=$(echo "$tmp_cmd" | sed -E 's/.*(connect:\/\/[^ ]*).*/\1/')

# Verify connection command validity
if [ -z "$connection_url" ]; then
    echo -e "${RED}Error: Could not extract a valid connection address, manual start required!${NC}"
    exit 1
fi

echo -e "${GREEN}--------------------${NC}"
echo -e "${GREEN}Starting lldb debugger...${NC}"
echo -e "${GREEN}⚠️⚠️⚠️ To launch the app, execute ${YELLOW}process connect $connection_url ${GREEN}and ${YELLOW}process launch${NC}"

# process connect execution may hang for unknown reasons, execute manually
lldb --one-line "platform select remote-ios" \
     --one-line "target create \"$APP_DIR\"" \
     --one-line "script lldb.target.module[0].SetPlatformFileSpec(lldb.SBFileSpec('$APP_PATH'))"
