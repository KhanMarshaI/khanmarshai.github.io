---
title: "Spookifier"
date: 2025-06-25 4:01:00 +0500
categories: [Challenges]
tags: [HTB, Web, SSTI]
---

## Reconnaissance
On visiting the website we are greeted with a heading, textbox, and a button. 

![alt text](/assets/images/spookifier.png)

To evaluate how the website works I use a simple string "Marshal" and enter it in the textbox. It just returns the same string but with different fonts.
There is no JavaScript on the website, but we can see googlefonts API being called.

```html
  <link href='https://fonts.googleapis.com/css?family=Press Start 2P' rel='stylesheet'>
```

There is bound to be a script on the backend that processes the string and returns different fonts. Our target is leveraging that script for our own use. Using any special characters like "--", "*", or numbers we are just shown the original string.

![alt text](/assets/images/spookifier_string.png)

We could test whether the scripts evaluate any mathematical expressions by injecting "2*3", however, it still returns the original string.

## Deductions

So far, we have observed the following:
1. User input is reflected verbatim.
2. Special characters or numbers alone aren't reflected with different fonts.

Such user input reflection usually open doors to injections. One such example is Server-Sided Template Injection (SSTI).

## Exploiting SSTI

Let's first confirm if the SSTI exists or not by testing the string `${2*3}` 

![alt text](/assets/images/spookifier_ssti.png)

Since our output is `6` we can confirm that SSTI does indeed exists.
On testing different payloads (github, PayloadAllThings) the conclusion is this is a sandboxed instance. We have to be clever. So far, only payload to work was `${7*7}` which made me inject some Java payloads resulting in server error. Afterwards, I tried injecting python `${print(1)}` which caused the fonts to be applied, however, the original string is returned as "None". Perhaps we could leverage python to read text files on the server?

One such function to read text files using python is `open().read()`. On injecting `${open("/flag,txt").read()}` we are shown the flag.

## Learnings
### Signs for Reflection-based Attack Surface

- Your input is echoed in the page, URL, headers, or error message
- You see unsanitized copies of your payload (e.g. `"><script>alert(1)</script>`)
- The app uses user input to build dynamic responses

### Resources

[Github](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Server%20Side%20Template%20Injection/README.md#mako)

