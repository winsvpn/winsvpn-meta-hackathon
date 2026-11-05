Option Explicit

If WScript.Arguments.Count <> 1 Then
    WScript.Quit 64
End If

Dim endpoint
endpoint = CStr(WScript.Arguments(0))
If LCase(Left(endpoint, 8)) <> "https://" And _
        LCase(Left(endpoint, 7)) <> "http://" Then
    WScript.Quit 65
End If

On Error Resume Next
Dim request
Set request = CreateObject("WinHttp.WinHttpRequest.5.1")
If Err.Number <> 0 Then
    WScript.StdErr.Write "WINHTTP_ERROR_HEX=" & Hex(Err.Number)
    WScript.Quit 66
End If
request.SetTimeouts 5000, 5000, 5000, 15000
request.Open "GET", endpoint, False
request.SetRequestHeader "Cache-Control", "no-cache"
request.Send
If Err.Number <> 0 Then
    WScript.StdErr.Write "WINHTTP_ERROR_HEX=" & Hex(Err.Number)
    WScript.Quit 67
End If
On Error GoTo 0

If request.Status <> 200 Then
    WScript.Quit 68
End If
WScript.StdOut.Write Trim(CStr(request.ResponseText))
