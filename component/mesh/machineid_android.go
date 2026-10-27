package mesh

// platformOSName is the system a phone runs, as a person would name it.
//
// The version would need android.os.Build, which lives behind a Java API this
// package cannot reach; the name alone is what the dashboard needs, and the
// device's identity no longer depends on anything the platform reports.
func platformOSName() string {
	return "Android"
}
