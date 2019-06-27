package burp

import java.net.URL


class BurpExtender: IBurpExtender {
    override fun registerExtenderCallbacks(callbacks: IBurpExtenderCallbacks) {
        callbacks.setExtensionName("Interesting Robots Only")
        callbacks.registerScannerCheck(ScannerCheck(callbacks))
    }
}


class ScannerCheck(val callbacks: IBurpExtenderCallbacks): IScannerCheck {
    val alreadyDoneHosts = mutableSetOf<String>()

    override fun consolidateDuplicateIssues(existingIssue: IScanIssue, newIssue: IScanIssue) = 0

    override fun doActiveScan(baseRequestResponse: IHttpRequestResponse, insertionPoint: IScannerInsertionPoint): List<IScanIssue> {

        val host = baseRequestResponse.httpService.host
        if (alreadyDoneHosts.contains(host)) {
            return emptyList()
        }
        alreadyDoneHosts.add(host)

        val url = with (baseRequestResponse.httpService) { URL(protocol, host, port, "/robots.txt") }
        val probeRequest = callbacks.helpers.buildHttpRequest(url)
        val responseObj = callbacks.makeHttpRequest(baseRequestResponse.httpService, probeRequest)
        val response = responseObj.response ?: return emptyList()
        val responseInfo = callbacks.helpers.analyzeResponse(response) // TODO: could NPE
        val robots = String(response.copyOfRange(responseInfo.bodyOffset, response.size))

        var boring = true
        for (line in robots.lines()) {
            callbacks.printOutput(line)
            if (line.trim().isEmpty() || line.startsWith("#")) {
                continue
            }
            if (line.startsWith("User-agent", ignoreCase = true)) {
            }
            else if (line.startsWith("Allow", ignoreCase = true) || line.startsWith("Disallow", ignoreCase = true)) {
                val value = line.substringAfter(":").trim()
                callbacks.printOutput("allow/dis $value")
                if (value.length > 1) {
                    boring = false
                    break
                }
            }
            else {
                callbacks.printOutput("misc false")
                boring = false
                break
            }
        }

        if (!boring) {
            return listOf(ScanIssue(url, arrayOf(responseObj), baseRequestResponse.httpService))
        }
        else {
            return emptyList()
        }

    }

    override fun doPassiveScan(baseRequestResponse: IHttpRequestResponse): List<IScanIssue> = emptyList()
}


class ScanIssue(
        override val url: URL,
        override val httpMessages: Array<IHttpRequestResponse>,
        override val httpService: IHttpService
): IScanIssue {
    override val confidence = "Certain"
    override val issueBackground = "The file robots.txt is used to give instructions to web robots, such as search engine crawlers, about locations within the web site that robots are allowed, or not allowed, to crawl and index.\n" +
            "The presence of the robots.txt does not in itself present any kind of security vulnerability. However, it is often used to identify restricted or private areas of a site's contents. The information in the file may therefore help an attacker to map out the site's contents, especially if some of the locations identified are not linked from elsewhere in the site. If the application relies on robots.txt to protect access to these areas, and does not enforce proper access control over them, then this presents a serious vulnerability."
    override val issueDetail = null
    override val issueName = "Interesting robots.txt discovered"
    override val issueType = 0x00600600
    override val remediationBackground = "The robots.txt file is not itself a security threat, and its correct use can represent good practice for non-security reasons. You should not assume that all web robots will honor the file's instructions. Rather, assume that attackers will pay close attention to any locations identified in the file. Do not rely on robots.txt to provide any kind of protection over unauthorized access."
    override val remediationDetail = null
    override val severity: String = "Information"
}
