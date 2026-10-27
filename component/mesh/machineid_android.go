package mesh

// platformMachineID has nothing to answer on Android: ANDROID_ID is read
// through the ContentResolver, so it reaches this package through
// SetHostIdentity from the JNI bridge, before any configuration is parsed.
//
// Returning empty here is the honest answer rather than a guess: a device that
// cannot read its own id must not invent one, because two devices inventing
// the same way would collide in the directory.
func platformMachineID() string {
	return ""
}

// platformOSName is supplied with the id by the same bridge ("Android 14"),
// since the version comes from android.os.Build rather than from a file.
func platformOSName() string {
	return ""
}
