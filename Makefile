TARGET := iphone:clang:latest:14.0
ARCHS = arm64 arm64e

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = SnapCloneEngine

SnapCloneEngine_FILES = Tweak.xm
SnapCloneEngine_CFLAGS = -fobjc-arc -fvisibility=hidden
SnapCloneEngine_FRAMEWORKS = Foundation Security CoreFoundation
SnapCloneEngine_LDFLAGS = -undefined dynamic_lookup

include $(THEOS_MAKEFILE_PATH)/tweak.mk
