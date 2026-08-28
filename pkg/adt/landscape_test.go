package adt

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// Sample SAP UI Landscape XML for testing
const testLandscapeXML = `<?xml version="1.0" encoding="UTF-8"?>
<Landscape version="1" updated="2025-01-15T10:00:00Z">
  <Messageservers>
    <Messageserver uuid="ms-uuid-001" name="S4H" host="msgserver.example.com" port="3600" description="S/4HANA Message Server"/>
    <Messageserver uuid="ms-uuid-002" name="ERP" host="erp-msg.example.com" port="3601" description="ERP Message Server" routerid="rtr-uuid-001"/>
  </Messageservers>
  <Routers>
    <Router uuid="rtr-uuid-001" name="Corporate Router" router="/H/saprouter.example.com/S/3299"/>
  </Routers>
  <Services>
    <Service uuid="svc-uuid-001" name="S4H [PUBLIC] SSO" type="SAPGUI"
             mode="0" msid="ms-uuid-001" server="PUBLIC"
             systemid="S4H"
             sncop="9" sncname="p:CN=S4H,O=MyOrg,C=DE"
             client="100" language="EN"/>
    <Service uuid="svc-uuid-002" name="S4H [PUBLIC] Basic" type="SAPGUI"
             mode="0" msid="ms-uuid-001" server="PUBLIC"
             systemid="S4H"
             client="100" language="EN"/>
    <Service uuid="svc-uuid-003" name="ERP Direct" type="SAPGUI"
             mode="1" server="erphost.example.com:3200"
             systemid="ERP" routerid="rtr-uuid-001"
             sncop="3" sncname="p:CN=ERP,O=MyOrg,C=DE"
             client="200" language="DE"/>
    <Service uuid="svc-uuid-004" name="ERP via LB" type="SAPGUI"
             mode="0" msid="ms-uuid-002" server="BATCH"
             sncop="1" sncname="p:CN=ERP,O=MyOrg,C=DE"
             client="200"/>
    <Service uuid="svc-uuid-005" name="DEV NoSNC" type="SAPGUI"
             mode="1" server="devhost.example.com:3210"
             systemid="DEV"
             client="001"/>
    <Service uuid="svc-uuid-006" name="QAS SNC NoSSO" type="SAPGUI"
             mode="1" server="qashost.example.com:3220"
             systemid="QAS"
             sncop="9" sncname="p:CN=QAS,O=MyOrg,C=DE" sncnosso="1"
             client="300"/>
    <Service uuid="svc-uuid-007" name="Fiori Launchpad" type="FIORI"
             url="https://fiori.example.com/sap/bc/ui5_ui5/ui2/ushell/shells/abap/FioriLaunchpad.html"/>
  </Services>
  <Workspaces>
    <Workspace uuid="ws-uuid-001" name="Development">
      <Item serviceid="svc-uuid-001"/>
      <Item serviceid="svc-uuid-005"/>
    </Workspace>
  </Workspaces>
</Landscape>`

func writeTempLandscape(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "SAPUILandscape.xml")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestParseLandscapeFile(t *testing.T) {
	path := writeTempLandscape(t, testLandscapeXML)

	landscape, err := ParseLandscapeFile(path)
	if err != nil {
		t.Fatalf("ParseLandscapeFile: %v", err)
	}

	// Check message servers
	if len(landscape.MessageServers) != 2 {
		t.Errorf("expected 2 message servers, got %d", len(landscape.MessageServers))
	}
	ms := landscape.MessageServers["ms-uuid-001"]
	if ms == nil {
		t.Fatal("message server ms-uuid-001 not found")
	}
	if ms.Name != "S4H" || ms.Host != "msgserver.example.com" || ms.Port != 3600 {
		t.Errorf("unexpected message server: %+v", ms)
	}

	// Check routers
	if len(landscape.Routers) != 1 {
		t.Errorf("expected 1 router, got %d", len(landscape.Routers))
	}
	rtr := landscape.Routers["rtr-uuid-001"]
	if rtr == nil || rtr.Router != "/H/saprouter.example.com/S/3299" {
		t.Errorf("unexpected router: %+v", rtr)
	}

	// Check services — only SAPGUI, not FIORI
	if len(landscape.Services) != 6 {
		t.Errorf("expected 6 SAPGUI services, got %d", len(landscape.Services))
	}
}

func TestFindSystemByID_PrefersSNC(t *testing.T) {
	path := writeTempLandscape(t, testLandscapeXML)
	landscape, err := ParseLandscapeFile(path)
	if err != nil {
		t.Fatal(err)
	}

	// S4H has two entries — should prefer the SNC-enabled one
	svc, err := landscape.FindSystemByID("S4H")
	if err != nil {
		t.Fatal(err)
	}
	if svc.UUID != "svc-uuid-001" {
		t.Errorf("expected SNC-enabled service svc-uuid-001, got %s", svc.UUID)
	}
	if svc.SNCOp != 9 || svc.SNCName != "p:CN=S4H,O=MyOrg,C=DE" {
		t.Errorf("unexpected SNC config: sncop=%d sncname=%s", svc.SNCOp, svc.SNCName)
	}
}

func TestFindSystemByID_ViaMessageServer(t *testing.T) {
	path := writeTempLandscape(t, testLandscapeXML)
	landscape, err := ParseLandscapeFile(path)
	if err != nil {
		t.Fatal(err)
	}

	// ERP has entries matching by both systemid and message server name
	svc, err := landscape.FindSystemByID("ERP")
	if err != nil {
		t.Fatal(err)
	}
	// Should find an SNC-enabled service
	if svc.SNCOp <= 0 {
		t.Errorf("expected SNC-enabled service for ERP, got sncop=%d", svc.SNCOp)
	}
}

func TestFindSystemByID_CaseInsensitive(t *testing.T) {
	path := writeTempLandscape(t, testLandscapeXML)
	landscape, err := ParseLandscapeFile(path)
	if err != nil {
		t.Fatal(err)
	}

	// Should work with lowercase
	svc, err := landscape.FindSystemByID("s4h")
	if err != nil {
		t.Fatal(err)
	}
	if svc.SystemID != "S4H" {
		t.Errorf("expected SystemID=S4H, got %s", svc.SystemID)
	}
}

func TestFindSystemByID_NotFound(t *testing.T) {
	path := writeTempLandscape(t, testLandscapeXML)
	landscape, err := ParseLandscapeFile(path)
	if err != nil {
		t.Fatal(err)
	}

	_, err = landscape.FindSystemByID("XXX")
	if err == nil {
		t.Error("expected error for non-existent system ID")
	}
}

func TestResolveSNCJcoProperties_LoadBalanced(t *testing.T) {
	path := writeTempLandscape(t, testLandscapeXML)

	props, err := ResolveSNCJcoProperties("S4H", path, "001", "EN")
	if err != nil {
		t.Fatalf("ResolveSNCJcoProperties: %v", err)
	}

	// SNC properties
	assertProp(t, props, "jco.client.snc_mode", "1")
	assertProp(t, props, "jco.client.snc_partnername", "p:CN=S4H,O=MyOrg,C=DE")
	assertProp(t, props, "jco.client.snc_qop", "9")

	// Connection properties (load balanced)
	assertProp(t, props, "jco.client.mshost", "msgserver.example.com")
	assertProp(t, props, "jco.client.msserv", "3600")
	assertProp(t, props, "jco.client.r3name", "S4H")
	assertProp(t, props, "jco.client.group", "PUBLIC")

	// Client/Language from landscape
	assertProp(t, props, "jco.client.client", "100")
	assertProp(t, props, "jco.client.lang", "EN")

	// Should NOT have direct connection properties
	if _, ok := props["jco.client.ashost"]; ok {
		t.Error("load-balanced connection should not have jco.client.ashost")
	}
}

func TestResolveSNCJcoProperties_DirectConnection(t *testing.T) {
	path := writeTempLandscape(t, testLandscapeXML)

	props, err := ResolveSNCJcoProperties("ERP", path, "001", "EN")
	if err != nil {
		t.Fatalf("ResolveSNCJcoProperties: %v", err)
	}

	// SNC properties
	assertProp(t, props, "jco.client.snc_mode", "1")
	assertProp(t, props, "jco.client.snc_partnername", "p:CN=ERP,O=MyOrg,C=DE")

	// Either direct or load-balanced — but must have connection info
	_, hasAsHost := props["jco.client.ashost"]
	_, hasMsHost := props["jco.client.mshost"]
	if !hasAsHost && !hasMsHost {
		t.Error("expected either jco.client.ashost or jco.client.mshost")
	}
}

func TestResolveSNCJcoProperties_DirectWithRouter(t *testing.T) {
	// Create a landscape with only the direct ERP service
	xml := `<?xml version="1.0" encoding="UTF-8"?>
<Landscape version="1">
  <Messageservers/>
  <Routers>
    <Router uuid="rtr-001" name="Router" router="/H/router.example.com/S/3299"/>
  </Routers>
  <Services>
    <Service uuid="svc-001" name="ERP Direct" type="SAPGUI"
             mode="1" server="erphost.example.com:3200"
             systemid="ERP" routerid="rtr-001"
             sncop="3" sncname="p:CN=ERP,O=MyOrg,C=DE"
             client="200" language="DE"/>
  </Services>
</Landscape>`
	path := writeTempLandscape(t, xml)

	props, err := ResolveSNCJcoProperties("ERP", path, "001", "EN")
	if err != nil {
		t.Fatalf("ResolveSNCJcoProperties: %v", err)
	}

	assertProp(t, props, "jco.client.ashost", "erphost.example.com")
	assertProp(t, props, "jco.client.sysnr", "00")
	assertProp(t, props, "jco.client.saprouter", "/H/router.example.com/S/3299")
	assertProp(t, props, "jco.client.client", "200")
	assertProp(t, props, "jco.client.lang", "DE")
}

func TestResolveSNCJcoProperties_NoSNC(t *testing.T) {
	path := writeTempLandscape(t, testLandscapeXML)

	_, err := ResolveSNCJcoProperties("DEV", path, "001", "EN")
	if err == nil {
		t.Error("expected error for system without SNC")
	}
}

func TestResolveSNCJcoProperties_SNCNoSSO(t *testing.T) {
	path := writeTempLandscape(t, testLandscapeXML)

	_, err := ResolveSNCJcoProperties("QAS", path, "001", "EN")
	if err == nil {
		t.Error("expected error for system with sncnosso=1")
	}
}

func TestResolveSNCJcoProperties_DefaultClientLanguage(t *testing.T) {
	// Service without client/language — should use defaults
	xml := `<?xml version="1.0" encoding="UTF-8"?>
<Landscape version="1">
  <Messageservers>
    <Messageserver uuid="ms-001" name="TST" host="tst-msg.example.com" port="3600"/>
  </Messageservers>
  <Routers/>
  <Services>
    <Service uuid="svc-001" name="TST LB" type="SAPGUI"
             mode="0" msid="ms-001" server="SPACE"
             systemid="TST"
             sncop="1" sncname="p:CN=TST,O=MyOrg,C=DE"/>
  </Services>
</Landscape>`
	path := writeTempLandscape(t, xml)

	props, err := ResolveSNCJcoProperties("TST", path, "800", "FR")
	if err != nil {
		t.Fatalf("ResolveSNCJcoProperties: %v", err)
	}

	assertProp(t, props, "jco.client.client", "800")
	assertProp(t, props, "jco.client.lang", "FR")
}

func TestParseLandscapeServerAddress(t *testing.T) {
	tests := []struct {
		server    string
		wantHost  string
		wantSysNr string
	}{
		{"myhost.example.com:3200", "myhost.example.com", "00"},
		{"myhost.example.com:3201", "myhost.example.com", "01"},
		{"myhost.example.com:3210", "myhost.example.com", "10"},
		{"myhost.example.com:8000", "myhost.example.com", ""}, // not 32xx format
		{"myhost.example.com", "myhost.example.com", ""},      // no port
		{"192.168.1.1:3200", "192.168.1.1", "00"},
	}

	for _, tt := range tests {
		host, sysNr := parseLandscapeServerAddress(tt.server)
		if host != tt.wantHost || sysNr != tt.wantSysNr {
			t.Errorf("parseLandscapeServerAddress(%q) = (%q, %q), want (%q, %q)",
				tt.server, host, sysNr, tt.wantHost, tt.wantSysNr)
		}
	}
}

func TestFindLandscapeFiles_ExplicitPath(t *testing.T) {
	path := writeTempLandscape(t, testLandscapeXML)

	files := FindLandscapeFiles(path)
	if len(files) == 0 {
		t.Error("expected at least 1 file")
	}
	if files[0] != path {
		t.Errorf("expected %s, got %s", path, files[0])
	}
}

func TestFindLandscapeFiles_NonexistentExplicit(t *testing.T) {
	files := FindLandscapeFiles("/nonexistent/path/landscape.xml")
	if len(files) != 0 {
		t.Errorf("expected 0 files for nonexistent path, got %d", len(files))
	}
}

func TestParseLandscapeFiles_Merge(t *testing.T) {
	dir := t.TempDir()

	// File 1: message server + service
	xml1 := `<?xml version="1.0" encoding="UTF-8"?>
<Landscape version="1">
  <Messageservers>
    <Messageserver uuid="ms-001" name="AAA" host="aaa-msg.example.com" port="3600"/>
  </Messageservers>
  <Services>
    <Service uuid="svc-001" name="AAA LB" type="SAPGUI"
             mode="0" msid="ms-001" server="PUBLIC"
             systemid="AAA" sncop="9" sncname="p:CN=AAA"/>
  </Services>
</Landscape>`

	// File 2: another service
	xml2 := `<?xml version="1.0" encoding="UTF-8"?>
<Landscape version="1">
  <Services>
    <Service uuid="svc-002" name="BBB Direct" type="SAPGUI"
             mode="1" server="bbb.example.com:3200"
             systemid="BBB" sncop="1" sncname="p:CN=BBB"/>
  </Services>
</Landscape>`

	path1 := filepath.Join(dir, "local.xml")
	path2 := filepath.Join(dir, "global.xml")
	os.WriteFile(path1, []byte(xml1), 0644)
	os.WriteFile(path2, []byte(xml2), 0644)

	landscape, err := ParseLandscapeFiles([]string{path1, path2})
	if err != nil {
		t.Fatal(err)
	}

	if len(landscape.Services) != 2 {
		t.Errorf("expected 2 services after merge, got %d", len(landscape.Services))
	}
	if len(landscape.MessageServers) != 1 {
		t.Errorf("expected 1 message server after merge, got %d", len(landscape.MessageServers))
	}
}

func TestGlobalFilePath(t *testing.T) {
	dir := t.TempDir()

	// Create both local and global files
	localPath := filepath.Join(dir, "SAPUILandscape.xml")
	globalPath := filepath.Join(dir, "SAPUILandscapeGlobal.xml")
	os.WriteFile(localPath, []byte("<Landscape/>"), 0644)
	os.WriteFile(globalPath, []byte("<Landscape/>"), 0644)

	result := landscapeGlobalFilePath(localPath)
	if result != globalPath {
		t.Errorf("expected %s, got %s", globalPath, result)
	}

	// SAPGUILandscape.xml doesn't have a naming convention for global
	javaPath := filepath.Join(dir, "SAPGUILandscape.xml")
	os.WriteFile(javaPath, []byte("<Landscape/>"), 0644)
	result = landscapeGlobalFilePath(javaPath)
	if result != "" {
		t.Errorf("expected empty for SAPGUILandscape.xml, got %s", result)
	}
}

func TestSNCLibraryScanDirsIncludesSecureLoginClientOnDarwin(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("macOS-specific SNC library path")
	}

	const secureLoginClientDir = "/Applications/Secure Login Client.app/Contents/MacOS/lib"
	for _, dir := range sncLibraryScanDirs() {
		if dir == secureLoginClientDir {
			return
		}
	}

	t.Errorf("SNC library scan directories do not contain %q", secureLoginClientDir)
}

func assertProp(t *testing.T, props map[string]string, key, expected string) {
	t.Helper()
	if val, ok := props[key]; !ok {
		t.Errorf("missing property %s", key)
	} else if val != expected {
		t.Errorf("property %s = %q, want %q", key, val, expected)
	}
}
