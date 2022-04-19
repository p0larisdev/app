all:
	xcodebuild clean build -configuration Debug CODE_SIGN_IDENTITY="" CODE_SIGNING_REQUIRED=NO CODE_SIGNING_ALLOWED=NO
	mkdir build/Debug-iphoneos/Payload
	mv build/Debug-iphoneos/p0laris.app build/Debug-iphoneos/Payload/
	cd build/Debug-iphoneos/; zip -r p0laris-Debug.ipa Payload; mv p0laris*.ipa ../../
#	cd ../../
#	xcodebuild archive -configuration Debug CODE_SIGN_IDENTITY="" CODE_SIGNING_REQUIRED=NO CODE_SIGNING_ALLOWED=NO -archivePath build/p0laris-Debug.xcarchive
#	xcodebuild -exportArchive -archivePath build/p0laris-Debug.xcarchive -exportPath build/ipa.	
	xcodebuild clean build -configuration Release CODE_SIGN_IDENTITY="" CODE_SIGNING_REQUIRED=NO CODE_SIGNING_ALLOWED=NO
	mv build/Release-iphoneos/p0laris.app build/Release-iphoneos/Payload/
	cd build/Release-iphoneos/; zip -r p0laris-Release.ipa Payload; mv p0laris*.ipa ../../
#	xcodebuild archive -configuration Release CODE_SIGN_IDENTITY="" CODE_SIGNING_REQUIRED=NO CODE_SIGNING_ALLOWED=NO
#	xcodebuild -exportArchive
