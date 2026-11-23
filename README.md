API RECON TOOL 

Authorized non - offensive API reconnaissance and IDOR/BOLA scanner. 

Maps an APIs real attack surface from its OpenAPI spec, then confirms broken object level authorization - BOLA, also called IDOR, for using test accounts you control. 

The difference from a one liner token swap: it runs the baseline and negative control request that separate a real finding from a false positive, so what lands in your report holds up. 
negative control request that separate a real finding from a false positive so what lands in your report holds up. 


WHY ANOTHER IDOR TOOL? 
Most IDOR checks stop at the "account B got a 200 fro account A's ID" That catches real bugs and a lot of noise alongside them:endpoints that ignore the ID entirely, endpoints that quietly return the callers own data, and data that was public to begin with. 
own data and data that was public to begin with. 

bola-recon sends five requests per endpoint and only reports CONFIRMED when the controls rule out each of those explanations:

#	Request	Question it answers	What it rules out
1	baseline — A → A's object	Does this request work at all?	A broken test setup
2	no-auth — no credentials → A's object	Is this object public anyway?	Public-by-design data
3	bogus-id — A → non-existent ID	Does the ID even matter?	Endpoints that ignore the ID
4	own-b — B → B's object	What does B's own data look like?	Endpoints scoped to the caller
5	cross — B → A's object	The BOLA test	—
