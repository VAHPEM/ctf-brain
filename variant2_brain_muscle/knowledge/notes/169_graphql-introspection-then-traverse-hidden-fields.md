---
tags: web graphql introspection schema api query endpoint curl burp
source: distilled/cssctf
---
For a GraphQL endpoint, run the introspection query {__schema{types{name fields{name}}}} (curl/GraphiQL/Burp) to dump the whole schema, then look for sensitive relations (e.g. an object's owner->description, user->secret) and write a traversal query that walks to the hidden data in one request. The app's own JS bundles usually reveal the /graphql endpoint path and sometimes field names. If introspection is disabled, infer fields from the client code.
