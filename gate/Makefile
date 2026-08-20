TARGET := iphone:clang:16.5:15.0
ARCHS = arm64 arm64e
INSTALL_TARGET_PROCESSES = FaceTime

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = KingVCamGate
KingVCamGate_FILES = Tweak.x
KingVCamGate_FRAMEWORKS = UIKit Foundation
KingVCamGate_CFLAGS = -fobjc-arc

include $(THEOS_MAKE_PATH)/tweak.mk
