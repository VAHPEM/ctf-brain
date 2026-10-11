---
tags: web ssrf oracle cloud gcp metadata bearer-token out-of-band tunnel resolver
source: distilled/cssctf
---
When a server fetches a URL you control (a resolver, webhook, avatar, callback), it's SSRF: point it at your own listener to see exactly what it sends, and build a length/content oracle by watching a numeric response field while you make it fetch controlled-size bodies. If public webhook sites are blocked, expose a local listener with an ssh reverse tunnel (e.g. ssh -R 80:localhost:8000 nokey@localhost.run). On cloud, aim the fetch at the instance metadata service to capture a short-lived bearer token (ya29... on GCP), then call tokeninfo / Secret Manager with Authorization: Bearer to read secrets; error messages often leak the project number you need.
