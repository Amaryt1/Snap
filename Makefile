TARGET := iphone:clang:latest:14.0
ARCHS = arm64 arm64e

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = SnapCloneEngine

SnapCloneEngine_FILES = Tweak.xm
SnapCloneEngine_CFLAGS = -fobjc-arc -fvisibility=hidden
SnapCloneEngine_FRAMEWORKS = Foundation Security CoreFoundation

include $(THEOS_MAKE_PATH)/tweak.mk
