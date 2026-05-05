SHELL := /bin/bash

SCHEME = MobileSecurityKit
BUILD_DIR = build
FRAMEWORK = $(BUILD_DIR)/$(SCHEME).xcframework/ios-arm64/$(SCHEME).framework/$(SCHEME)

.PHONY: xcframework _assemble-xcframework audit clean

xcframework:
	@echo "Building iOS device..."
	@set -o pipefail; xcodebuild archive \
		-scheme $(SCHEME) \
		-destination "generic/platform=iOS" \
		-archivePath $(BUILD_DIR)/$(SCHEME)-iOS.xcarchive \
		SKIP_INSTALL=NO \
		BUILD_LIBRARY_FOR_DISTRIBUTION=YES \
		INSTALL_PATH=/Library/Frameworks \
		| xcpretty

	@echo "Building iOS Simulator..."
	@set -o pipefail; xcodebuild archive \
		-scheme $(SCHEME) \
		-destination "generic/platform=iOS Simulator" \
		-archivePath $(BUILD_DIR)/$(SCHEME)-Sim.xcarchive \
		SKIP_INSTALL=NO \
		BUILD_LIBRARY_FOR_DISTRIBUTION=YES \
		INSTALL_PATH=/Library/Frameworks \
		ARCHS="arm64 x86_64" \
		EXCLUDED_ARCHS="" \
		| xcpretty

	@echo "Creating XCFramework..."
	rm -rf $(BUILD_DIR)/$(SCHEME).xcframework
	xcodebuild -create-xcframework \
		-framework $(BUILD_DIR)/$(SCHEME)-iOS.xcarchive/Products/Library/Frameworks/$(SCHEME).framework \
		-framework $(BUILD_DIR)/$(SCHEME)-Sim.xcarchive/Products/Library/Frameworks/$(SCHEME).framework \
		-output $(BUILD_DIR)/$(SCHEME).xcframework \
	|| $(MAKE) _assemble-xcframework

_assemble-xcframework:
	@echo "Falling back to manual XCFramework assembly..."
	@DEVICE_FW="$(BUILD_DIR)/$(SCHEME)-iOS.xcarchive/Products/Library/Frameworks/$(SCHEME).framework"; \
	SIM_FW="$(BUILD_DIR)/$(SCHEME)-Sim.xcarchive/Products/Library/Frameworks/$(SCHEME).framework"; \
	OUT="$(BUILD_DIR)/$(SCHEME).xcframework"; \
	rm -rf "$$OUT"; \
	mkdir -p "$$OUT/ios-arm64/$(SCHEME).framework"; \
	mkdir -p "$$OUT/ios-arm64_x86_64-simulator/$(SCHEME).framework"; \
	cp -r "$$DEVICE_FW/" "$$OUT/ios-arm64/$(SCHEME).framework/"; \
	cp -r "$$SIM_FW/" "$$OUT/ios-arm64_x86_64-simulator/$(SCHEME).framework/"; \
	/usr/libexec/PlistBuddy -c "Add :CFBundlePackageType string XFWK" \
		-c "Add :XCFrameworkFormatVersion string 1.0" \
		-c "Add :AvailableLibraries array" \
		-c "Add :AvailableLibraries:0 dict" \
		-c "Add :AvailableLibraries:0:LibraryIdentifier string ios-arm64" \
		-c "Add :AvailableLibraries:0:LibraryPath string $(SCHEME).framework" \
		-c "Add :AvailableLibraries:0:SupportedArchitectures array" \
		-c "Add :AvailableLibraries:0:SupportedArchitectures:0 string arm64" \
		-c "Add :AvailableLibraries:0:SupportedPlatform string ios" \
		-c "Add :AvailableLibraries:1 dict" \
		-c "Add :AvailableLibraries:1:LibraryIdentifier string ios-arm64_x86_64-simulator" \
		-c "Add :AvailableLibraries:1:LibraryPath string $(SCHEME).framework" \
		-c "Add :AvailableLibraries:1:SupportedArchitectures array" \
		-c "Add :AvailableLibraries:1:SupportedArchitectures:0 string arm64" \
		-c "Add :AvailableLibraries:1:SupportedArchitectures:1 string x86_64" \
		-c "Add :AvailableLibraries:1:SupportedPlatform string ios" \
		-c "Add :AvailableLibraries:1:SupportedPlatformVariant string simulator" \
		"$$OUT/Info.plist"

	@echo "Done: $(BUILD_DIR)/$(SCHEME).xcframework"

audit:
	@if [ ! -f "$(FRAMEWORK)" ]; then echo "ERROR: Run 'make xcframework' first."; exit 1; fi
	@echo ""
	@echo "=============================="
	@echo " MobileSecurityKit Audit"
	@echo "=============================="
	@PASS=0; FAIL=0; WARN=0; \
	\
	echo ""; \
	echo "[ 1 ] Debug symbols (DWARF)"; \
	DWARF=$$(dwarfdump --debug-info "$(FRAMEWORK)" 2>/dev/null | grep -c "DW_TAG_compile_unit" || true); \
	if [ "$$DWARF" -eq 0 ]; then \
		echo "  PASS  No DWARF debug info in binary"; PASS=$$((PASS+1)); \
	else \
		echo "  FAIL  DWARF debug info present ($$DWARF compile units) — strip before distributing"; FAIL=$$((FAIL+1)); \
	fi; \
	\
	echo ""; \
	echo "[ 2 ] Stack protection (canary)"; \
	CANARY=$$(nm "$(FRAMEWORK)" 2>/dev/null | grep -c "___stack_chk_guard" || true); \
	if [ "$$CANARY" -gt 0 ]; then \
		echo "  PASS  Stack canary reference found"; PASS=$$((PASS+1)); \
	else \
		echo "  WARN  No stack canary — expected for Swift-only binaries, verify intentional"; WARN=$$((WARN+1)); \
	fi; \
	\
	echo ""; \
	echo "[ 3 ] Position Independent Code (PIE/ASLR)"; \
	FLAGS=$$(otool -hv "$(FRAMEWORK)" 2>/dev/null | grep -c "PIE" || true); \
	if [ "$$FLAGS" -gt 0 ]; then \
		echo "  PASS  PIE flag set"; PASS=$$((PASS+1)); \
	else \
		echo "  WARN  PIE flag not set — ASLR may not apply (normal for arm64 frameworks)"; WARN=$$((WARN+1)); \
	fi; \
	\
	echo ""; \
	echo "[ 4 ] Code signing"; \
	SIGNED=$$(codesign -v "$(FRAMEWORK)" 2>&1 | grep -c "satisfies" || true); \
	if [ "$$SIGNED" -gt 0 ]; then \
		echo "  PASS  Binary is signed"; PASS=$$((PASS+1)); \
	else \
		SIG=$$(codesign -dv "$(FRAMEWORK)" 2>&1 | grep -c "Identifier" || true); \
		if [ "$$SIG" -gt 0 ]; then \
			echo "  PASS  Binary is signed"; PASS=$$((PASS+1)); \
		else \
			echo "  WARN  Binary is not signed (sign before distribution)"; WARN=$$((WARN+1)); \
		fi; \
	fi; \
	\
	echo ""; \
	echo "[ 5 ] Symbol visibility — exported symbols"; \
	TOTAL=$$(nm -gU "$(FRAMEWORK)" 2>/dev/null | wc -l | tr -d ' '); \
	INTERNAL=$$(nm -gU "$(FRAMEWORK)" 2>/dev/null | grep -v "\$s$(SCHEME)" | grep -v "___swift" | grep -v "_swift_" | grep -c "T " || true); \
	echo "  INFO  $$TOTAL exported symbol(s), $$INTERNAL non-Swift exported symbol(s)"; \
	if [ "$$INTERNAL" -eq 0 ]; then \
		echo "  PASS  No unexpected symbols exported"; PASS=$$((PASS+1)); \
	else \
		echo "  WARN  Review exported symbols below:"; WARN=$$((WARN+1)); \
		nm -gU "$(FRAMEWORK)" 2>/dev/null | grep -v "\$s$(SCHEME)" | grep -v "___swift" | grep -v "_swift_" | grep "T " | head -20; \
	fi; \
	\
	echo ""; \
	echo "[ 6 ] Weak / undefined symbols"; \
	WEAK=$$(nm -u "$(FRAMEWORK)" 2>/dev/null | grep -vc "dyld_stub_binder\|___stack_chk\|_swift_\|___swift\|__objc" || true); \
	if [ "$$WEAK" -eq 0 ]; then \
		echo "  PASS  No unexpected undefined symbols"; PASS=$$((PASS+1)); \
	else \
		echo "  WARN  $$WEAK unexpected undefined symbol(s) — review for hijack surface"; WARN=$$((WARN+1)); \
		nm -u "$(FRAMEWORK)" 2>/dev/null | grep -v "dyld_stub_binder\|___stack_chk\|_swift_\|___swift\|__objc" | head -10; \
	fi; \
	\
	echo ""; \
	echo "[ 7 ] Objective-C metadata leakage"; \
	OBJC=$$(otool -ov "$(FRAMEWORK)" 2>/dev/null | grep -c "class name" || true); \
	if [ "$$OBJC" -eq 0 ]; then \
		echo "  PASS  No ObjC class metadata found"; PASS=$$((PASS+1)); \
	else \
		echo "  WARN  $$OBJC ObjC class(es) exposed — verify intentional:"; WARN=$$((WARN+1)); \
		otool -ov "$(FRAMEWORK)" 2>/dev/null | grep "class name" | head -10; \
	fi; \
	\
	echo ""; \
	echo "[ 8 ] Bitcode"; \
	BC=$$(otool -l "$(FRAMEWORK)" 2>/dev/null | grep -c "__LLVM" || true); \
	if [ "$$BC" -gt 0 ]; then \
		echo "  PASS  Bitcode section present"; PASS=$$((PASS+1)); \
	else \
		echo "  WARN  No bitcode — acceptable for direct distribution, required for some App Store flows"; WARN=$$((WARN+1)); \
	fi; \
	\
	echo ""; \
	echo "------------------------------"; \
	echo " PASS: $$PASS  WARN: $$WARN  FAIL: $$FAIL"; \
	echo "------------------------------"; \
	echo ""; \
	if [ "$$FAIL" -gt 0 ]; then exit 1; fi

clean:
	rm -rf $(BUILD_DIR)
