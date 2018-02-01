# DogWhisperer - BloodHound Cypher Cheat Sheet (v2)

Collection of **BloodHound Cypher Query Examples**

* [I- Raw](#i--raw)
* [II- Built-In](#ii--built-in)
* [III- Custom](#iii--custom)
* [IV- DB Manipulation](#iv--db-manipulation)
* [V- REST API](#v--rest-api) _(PowerShell)_

_see also [Neo4j Syntax Reference](http://neo4j.com/docs/cypher-refcard/current/) for more Cypher madness_

This is a **quick guide** and is not ment to be exhaustive or anything. Just a collection of bits and pieces I found here and there. Enough to start **scratching the surface** by looking at some **examples**, but surely not enough to master the full power of **BloodHound Cypher Queries**.

For advance BloodHound Cypher, [check the pros...](#moaaar-stuff)

_Note: All examples in this guide can be run against the [Bloodhound sample database](#sample-db) for testing_

![HostBusters](https://github.com/SadProcessor/Cheats/blob/master/HostBustersWallpaper.jpg)

<br><br/>

***

## I- Raw

Can be entered in the **Raw Query** input box at the bottom of the BloodHound UI

### A- Nodes

#### All Nodes
```
MATCH (n) RETURN n
```
<br><br/>
#### All User Nodes (Computer/Group/Domain)
```
MATCH (n:User) RETURN n
```
<br><br/>
#### Node by Name
```
MATCH (x:Computer {name: 'APOLLO.EXTERNAL.LOCAL'}) RETURN x
```
> Return Computer node name 'APOLLO.EXTERNAL.LOCAL'

```
MATCH (x:Computer) WHERE x.name='APOLLO.EXTERNAL.LOCAL' RETURN x
```
> Same as above, different syntax

```
MATCH (x) WHERE x.name='APOLLO.EXTERNAL.LOCAL' RETURN x
```
> Same without specifying node type (probably less eco-friendly)

<br><br/>
#### Node by Property - Property Exists
```
MATCH (n:User) WHERE exists(n.test) RETURN n
```
> Return all nodes that have a property 'test' (value or not)

<br><br/>
#### Node by Property - Does Not Exists
```
MATCH (n:User) WHERE NOT exists(n.test) RETURN n
```
> Return all user that dont have a property called 'test'

<br><br/>
#### Node by Property - Property Value
```
MATCH (n:User) WHERE n.test='helloWorld' RETURN n
```
> Return all user that have a property 'test' with value 'helloworld'

```
MATCH (X:Group) WHERE X.name CONTAINS 'ADMIN' RETURN X
```
> Return All Groups with 'ADMIN' in name (case sensitive)

```
MATCH (X:Group) WHERE X.name =~ '(?i).*aDMiN.*' RETURN X
```
> Same as above, using (case insensitive) regex

<br><br/>
#### Comparaison Operators

List of operators that can be used with the `WHERE` clause

| OPERATOR | SYNTAX |
| ---: | :--- |
| Is Equal To | `=` |
| Is Not Equal To | `<>` |
| Is Less Than | `<` |
| Is Greater Than | `>` |
| Is Less or Equal | `<=` |
| Is Greater or Equal | `>=` |
| Is Null | `IS NULL` |
| Us Not Null |`IS NOT NULL`|
| Prefix Search \* | `STARTS WITH`|
| Suffix Search \* | `ENDS WITH`|
| Inclusion Search \* | `CONTAINS`|
| Regex \* | `=~` |

\* String specific

<br><br/>
### B- Edges

> TIP: It's possible to **paste multi-lines** in the query box

#### Group Membership - Direct

```
MATCH 
(A:User),
(B:Group {name: 'CONTRACTINGH@INTERNAL.LOCAL'}),
p=(A)-[r:MemberOf*1..1]->(B) 
RETURN p
```

#### Group Membership - Degree 4

```
MATCH 
(A:User), 
(B:Group {name: 'CONTRACTINGH@INTERNAL.LOCAL'}), 
p=(A)-[r:MemberOf*1..4]->(B) 
RETURN p
```

#### Group Mambership -Any degree

```
MATCH 
(A:User), 
(B:Group {name: 'CONTRACTINGH@INTERNAL.LOCAL'}), 
p=(A)-[r:MemberOf*1..]->(B) 
RETURN p
```

<br><br/>
List of **available Edges** types (ACL since 1.3)

| Source Node Type | Edge Type | Target Node Type |
| :---: | :---: | :---: |
| User/Group | `:MemberOf` | Group |
| User/Group | `:AdminTo` | Computer |
| Computer | `:HasSession` | User |
| Domain | `:TrustedBy` | Domain |
|  User/Group | `:ForceChangePassword` \* | User |
|  User/Group | `:AddMembers` \* | Group |
|  User/Group | `:GenericAll` \* | User/Computer/Group |
|  User/Group | `:GenericWrite` \* | User/Computer/Group |
|  User/Group | `:WriteOwner` \* | User/Computer/Group|
|  User/Group | `:WriteDACL` \* | User/Computer/Group |
|  User/Group | `:AllExtendedRights` \* | User/Computer/Group |

\* More info on [ACLs](https://wald0.com/?p=112)

<br><br/>
### C- Paths

#### Shortest Path from A to B - any Edge type
```
MATCH
(A:User {name: 'ACHAVARIN@EXTERNAL.LOCAL'}),
(B:Group {name: 'DOMAIN ADMINS@INTERNAL.LOCAL'}),
x=shortestPath((A)-[*1..]->(B))
RETURN x
```

#### Shortest Path from A to B - specific Edge types
```
MATCH
(A:User {name: 'ACHAVARIN@EXTERNAL.LOCAL'}),
(B:Group {name: 'DOMAIN ADMINS@INTERNAL.LOCAL'}),
x=shortestPath((A)-[:HasSession|:AdminTo|:MemberOf*1..]->(B))
RETURN x
```

#### Advanced Path
```
MATCH
(A:User),
(B:Computer {name: 'WEBSERVER3.INTERNAL.LOCAL'}),
p=(A)-[r:MemberOf|:AdminTo*1..3]->(B)
RETURN p
```
> All admin user max 3 hops away by group membership from specified target computer

#### All Sortest Paths
```
MATCH
(A:User {name: 'ACHAVARIN@EXTERNAL.LOCAL'}),
(B:Group {name: 'DOMAIN ADMINS@INTERNAL.LOCAL'}),
x=allShortestPaths((A)-[*1..]->(B))
RETURN x
```
The `allShortestPaths()` function works the same way as `shortestPath()` but returns all possible shortest path 

(= more ways to get to target with same amount of hops) 

/!\ Restrict _Edge type_ / _max hops_ for heavy queries

<br><br/>
#### Union
Multiple returned results can be combined into a single output/graph using `UNION` or `UNION ALL`

In this Example a **Path from A to B via C**
```
MATCH 
(A:User {name: 'ACHAVARIN@EXTERNAL.LOCAL'}), 
(C:User {name: 'CBARCLAY@INTERNAL.LOCAL'}), 
x=shortestPath((A)-[*1..]->(C)) 
RETURN x 
UNION ALL 
MATCH 
(C:User {name: 'CBARCLAY@INTERNAL.LOCAL'}),
(B:Group {name: 'DOMAIN USERS@INTERNAL.LOCAL'}),
x=shortestPath((C)-[*0..]->(B))
RETURN x
```

<br><br/>

***

## II- Built-In

Commonly used queries. Found under the Query Tab. 

Avoids having to come up with syntax every time.

A lot of cool example in there.

_source code can be found [here](https://github.com/BloodHoundAD/BloodHound/blob/master/src/components/SearchContainer/Tabs/PrebuiltQueries.json)_

Below is there equivalent syntax if you were to insert them in the Query Box.

### All Domain Admin
```
MATCH (n:Group) WHERE n.name =~ "(?i).*DOMAIN ADMINS.*"
WITH n 
MATCH (n)<-[r:MemberOf*1..]-(m) 
RETURN n,r,m
```

### Shortest Path to Domain Admin
```
MATCH 
(n:User),
(m:Group {name: 'DOMAIN ADMINS@INTERNAL.LOCAL'}),
p=shortestPath((n)-[*1..]->(m))
RETURN p
```

### All Logged in Admins
```
MATCH 
p=(a:Computer)-[r:HasSession]->(b:User) 
WITH a,b,r 
MATCH 
p=shortestPath((b)-[:AdminTo|MemberOf*1..]->(a)) 
RETURN b,a,r 
```

### Top 10 Users with Most Sessions
```
MATCH 
(n:User),(m:Computer),
(n)<-[r:HasSession]-(m) 
WHERE NOT n.name STARTS WITH 'ANONYMOUS LOGON' 
AND NOT n.name='' WITH n, 
count(r) as rel_count 
order by rel_count desc 
LIMIT 10 
MATCH 
(m)-[r:HasSession]->(n) 
RETURN n,r,m
```

### Top 10 Users with Most Local Admin Rights
```
MATCH
(n:User),
(m:Computer),
(n)-[r:AdminTo]->(m)
WHERE NOT n.name STARTS WITH 'ANONYMOUS LOGON' 
AND NOT n.name='' WITH n, 
count(r) as rel_count 
order by rel_count desc 
LIMIT 10 
MATCH 
(m)<-[r:AdminTo]-(n) 
RETURN n,r,m 
```

### Top 10 Computers with Most Admins
```
MATCH 
(n:User),
(m:Computer),
(n)-[r:AdminTo]->(m)
WHERE NOT n.name STARTS WITH 'ANONYMOUS LOGON' 
AND NOT n.name='' WITH m,
count(r) as rel_count 
order by rel_count desc 
LIMIT 10 
MATCH 
(m)<-[r:AdminTo]-(n) 
RETURN n,r,m  
```

### Users with Foreign Domain Group Membership
```
MATCH 
(n:User) 
WHERE n.name ENDS WITH ('@' + 'INTERNAL.LOCAL') 
WITH n 
MATCH (n)-[r:MemberOf]->(m:Group) 
WHERE NOT m.name ENDS WITH ('@' + 'INTERNAL.LOCAL') 
RETURN n,r,m
```

### Groups with Foreign Group Membership
```
MATCH
(n:Group)
WHERE n.name ENDS WITH '@EXTERNAL.LOCAL'
WITH n 
MATCH 
(n)-[r:MemberOf*1..]->(m:Group) 
WHERE NOT m.name ENDS WITH '@EXTERNAL.LOCAL'
RETURN n,r,m
```

### Map Domain Trusts
```
MATCH (n:Domain) MATCH p=(n)-[r]-() RETURN p
```

<br><br/>
***

## III- Custom

Add **homemade** queries to the interface (= ease of use).

**Looks & feels exactly like built-in queries** once added.

To add custom queries, click on the pen icon all the way at the bottom of the query tab.

Open in Notepad. Paste Query.

/!\ Don't forget to save changes.

Will be saved to `C:\Users\<username>\AppData\Roaming\bloodhound\customqueries`. 

Click on refresh icon next to pen. 

Voila.

_Check [Built-In](#ii--built-in) query source code for syntax examples_

_Check @cptjesus [intro to Cypher](https://blog.cptjesus.com/posts/introtocypher) for more info_

<br><br/>

***

## IV- DB Manipulation

Add/Delete Nodes/Properties/Edges to/from DB. (The world is yours...)

### Create Node
```
MERGE (n:User {name: 'bob'})
```
> Creates Node if doesn't already exist

<br><br/>
### Add/Update Node property
```
MATCH (n) WHERE n.name='bob' SET n.age=23
```

```
MATCH (n) WHERE n.name='bob' SET n.age=27, n.hair='black', n.sport='Chess-Boxing'
```
> Both Create missing properties, overwrites existing property values

<br><br/>
### Remove Node property
```
MATCH (n) WHERE n.name='Bob' REMOVE n.sport
```

```
MATCH (U:User) WHERE EXISTS(U.age) REMOVE U.age
```

```
MATCH (U:User) WHERE EXISTS(U.hair) REMOVE U.age, U.hair RETURN U
```
> Removes property from node (Single Node / multiple Nodes / multiple props) 

<br><br/>
### Create Edge between Nodes (/!\ direction)

```
MATCH (A:User {name: 'alice'}) 
MATCH (B:User {name: 'bob'}) 
CREATE (A)-[r:IsSister]->(B)
```

```
MATCH (A:User {name: 'alice'}) 
MATCH (B:User {name: 'bob'}) 
CREATE (A)<-[r:IsBrother]-(B)
```
<br><br/>
### Delete Edge
```
MATCH (n:User {name: 'alice'})-[r:IsSister]->(m:User {name: 'bob'}) 
DELETE r
```

> /!\ not specifying any Edge type will remove all Edges between specified Nodes

<br><br/>
### Delete Node (and all connected edges)
```
MATCH (n:User {name: 'bob'}) DETACH DELETE n
```

<br><br/>
### Create Node & Properties 

 **/!\ DANGER ZONE /!\\**

```
MERGE (n:User {name: 'alice', age:23, hair:'black'}) RETURN n
```
> /!\ Use only if Node name doesn't already exist. Prefer safer MERGE/SET command

### Create nodes & Properties & Edges 
```
MERGE (A:User {name:bob})-[r:IsBrother]->(B:User {name:'Paul'})
```

```
MERGE (A:User {name:'Jack', age:14, hair:'black'})-[r:IsBrother]->(B:User {name:'Jimmy'})
```
> /!\ Use only if Nodes don't already exist. otherwise MERGE or MERGE/SET each block sperately

**Recommended syntax**:
```
MERGE (A:User {name:'bob'})
MERGE (B:User {name: 'Paul'})
MERGE (A)-[r:IsBrother]->(B)
```

```
MERGE(X:User {name:'Jack'}) SET X.age=14, X.hair='black' 
MERGE(Y:User {name:'Jimmy'}) SET Y.age=21, X.hair='black' 
MERGE (X)-[r:IsBrother]->(Y)
```

### Nuke DB
```
MATCH (x) DETACH DELETE x
```
> /!\ Simple and efficient. Try at your own (data) expense

<br><br/>

***

## V- REST API

Access/Manipulate **BloodHound data via REST API**. 

Example here is with PowerShell, but you can apply same method with language of your choosing.

Note: To Access Bloodhound (on localhost) via API, uncomment `#dbms.security.auth_enabled=false` in neo4j config file

### API Call - Basic

```PowerShell
# Prep Vars 
$Server = 'localhost'
$Port   = '7474'
$Uri    = "http://$Server:$Port/db/data/cypher"
$Header = @{'Accept'='application/json; charset=UTF-8';'Content-Type'='application/json'}
$Method = 'POST'
$Body   = '----- tbd -----'

# Make Call
$Reply = Invoke-RestMethod -Uri $Uri -Method $Method -Headers $Header -Body $Body
# Node Data
$NodeData = $Reply.data.data

```

> Only need to add `$Body` to build query. The rest stays the same. See examples below...

### A- Node

#### Node View

```Powershell
$Body = '{
"query" : "MATCH (A:Computer {name: {ParamA}}) RETURN A",
"params" : { "ParamA" : "APOLLO.EXTERNAL.LOCAL" }
}'
```

#### Node New

```Powershell
$Body = '{
"query" : "MERGE (n:User {name: {P1}}) RETURN n",
"params" : { "P1" : "bob" }
}'
```

#### Node Add Property / Update Value

```Powershell
$Body = '{
"query"  : "MATCH (n) WHERE n.name={Usr} SET n.number={Val}",
"params" : { "Usr" : "bob", "Val" : 8 }
}'
```

#### Node remove property

```Powershell
$Body = '{
"query" : "MATCH (n) WHERE n.name={input} REMOVE n.number",
"params": {"input": "Alice"}
}'
```

#### Node Delete

```Powershell
$Body = '{
"query" : "MATCH (n:User {name: {thisname}}) DETACH DELETE n",
"params": { "thisname" : "bob" }
}'
```

### B- Edge

#### Edge View

```Powershell
$Body = '{
"query" : "MATCH (A:User),(B:User {name: {ParamB}}) MATCH p=(A)-[r:MemberOf*1..1]->(B) RETURN A",
"params" : { "ParamB" : "AUDIT_B@EXTERNAL.LOCAL" }
}'
```

#### Edge Create
```Powershell
$Body = '{
"query" : "MERGE (n:User {name: {U1}}) MERGE (m:User {name: {U2}}) MERGE (m)-[r:IsSister]->(n)",
"params": { "U1" : "bob", "U2" : "alice"}
}'
```

### C- Path

#### Shortest Path 

```Powershell
$Body = '{
"query" : "MATCH (A:User {name: {ParamA}}), (B:Group {name: {ParamB}}), x=shortestPath((A)-[*1..]->(B)) RETURN x",
"params" : { "ParamA" : "ACHAVARIN@EXTERNAL.LOCAL", "ParamB" : "DOMAIN ADMINS@EXTERNAL.LOCAL" }
}'
```

<br><br/>
#### Putting it all together...
Post to server. Get reply. Parse data. Automate other stuff with that data... Fantastic!

![GreatestDogInTheWorld](https://github.com/SadProcessor/Cheats/blob/master/MostImportantDog.png)

A basic **PowerShell** function to call the API could look like this...

```Powershell
## Function
function Invoke-DogPost{
    [CmdletBinding()]
    [Alias('DogPost')]
    Param(
        [Parameter(Mandatory=1)][string]$Body,
        [Parameter()][String]$Server='localhost',
        [Parameter()][int]$Port=7474,
        [Parameter()][Switch]$RawData
        )
    $Uri = "http://${Server}:${Port}/db/data/cypher"
    $Header=@{'Accept'='application/json; charset=UTF-8';'Content-Type'='application/json'}
    $Result = Try{Invoke-RestMethod -Uri $Uri -Method Post -Headers $Header -Body $Body}Catch{$Error[0].Exception}
    if($RawData){Return $result}
    else{Return $Result.data.data}
    }

## TestCall
$Body='
{
"query" : "MATCH (A:Computer {name: {ParamA}}) RETURN A",
"params" : { "ParamA" : "APOLLO.EXTERNAL.LOCAL" }
}
'
DogPost $Body

```

> _Works exact same way with a `curl` on linux_

<br><br/>
**Attackers Think in Graph... Automations Don't.**

Returning Graphs is not suited for all command line tools (ba dum tsss!), but computers love data...

Return Nodes, or parse Paths into Objects

_Example: (just an idea)_

```
Step StartNode                             Edge       Direction EndNode                              
---- ---------                             ----       --------- -------                              
   0 ACHAVARIN@EXTERNAL.LOCAL              MemberOf   ->        INFORMATIONTECHNOLOGY7@EXTERNAL.LOCAL
   1 INFORMATIONTECHNOLOGY7@EXTERNAL.LOCAL MemberOf   ->        DOMAIN ADMINS@EXTERNAL.LOCAL         
   2 DOMAIN ADMINS@EXTERNAL.LOCAL          AdminTo    ->        DESKTOP11.EXTERNAL.LOCAL             
   3 DESKTOP11.EXTERNAL.LOCAL              HasSession ->        AMEADORS@EXTERNAL.LOCAL              
   4 AMEADORS@EXTERNAL.LOCAL               MemberOf   ->        CONTRACTINGF@INTERNAL.LOCAL          
   5 CONTRACTINGF@INTERNAL.LOCAL           MemberOf   ->        CONTRACTINGG@INTERNAL.LOCAL          
   6 CONTRACTINGG@INTERNAL.LOCAL           MemberOf   ->        CONTRACTINGH@INTERNAL.LOCAL          
   7 CONTRACTINGH@INTERNAL.LOCAL           MemberOf   ->        CONTRACTINGI@INTERNAL.LOCAL          
   8 CONTRACTINGI@INTERNAL.LOCAL           AdminTo    ->        MANAGEMENT7.INTERNAL.LOCAL           
   9 MANAGEMENT7.INTERNAL.LOCAL            HasSession ->        ASANDERS.ADMIN@INTERNAL.LOCAL        
  10 ASANDERS.ADMIN@INTERNAL.LOCAL         MemberOf   ->        DOMAIN ADMINS@INTERNAL.LOCAL
```

<br><br/>

***

## Moaaar Stuff

### Useful links

Links to more info on/around the topic

#### **Github**

- [BloodHound Code](https://github.com/BloodHoundAD/BloodHound)

- [Wiki](https://github.com/BloodHoundAD/BloodHound/wiki)

#### **Twitter**

- [@harmj0y](https://twitter.com/harmj0y) Click on Follow...

- [@_wald0](https://twitter.com/_wald0) Click on Follow...

- [@CptJesus](https://twitter.com/CptJesus) Click on Follow...

- [@Porterhau5](https://twitter.com/porterhau5) Click on Follow

#### **Slack**

- [Channel Here](https://bloodhoundhq.slack.com/messages/general/) get invite [here](https://bloodhoundgang.herokuapp.com/)

#### **Blog**

- [Introducing BloodHound](https://wald0.com/?p=68) by @_wald0

- [Intro to Cypher](https://blog.cptjesus.com/posts/introtocypher) by @CptJesus

- [ACL Attack Paths](https://wald0.com/?p=112) by @_wald0

- [Extending Bloodhound...](https://porterhau5.com/blog/extending-bloodhound-track-and-visualize-your-compromise/) by @Porterhau5

- [Representing Password Reuse in BloodHound](https://porterhau5.com/blog/representing-password-reuse-in-bloodhound/) by @Porterhau5

#### **Video**

- [Six degrees of Domain Admin](https://youtu.be/lxd2rerVsLo) by @_wald0 & Co - BSides LV 2016

- [Here Be Dragons...](https://youtu.be/z8thoG7gPd0) by @_wald0 & Co - DerbyCon 2017 

- [GoFetch](https://youtu.be/lbJPCnjQxCU) by @TaltheMaor @TalBerySec - BlackHat 2017

- [Extending Bloodhound for RedTeamers](https://youtu.be/Pn7GWRXfgeI) by @Porterhau5 - WWHF 2017

- [Requiem for an Admin](https://youtu.be/uMg18TvLAcE?list=PLdhDuST3OlrNRull1hITtWVYzIQPfWjXD) by @SadProcessor - BSides Amsterdam 2017 (Shameless Plug)

#### **Noe4j**

- [Cypher Reference Card](http://neo4j.com/docs/cypher-refcard/current/)

- [Cypher Syntax Online Documentation](https://neo4j.com/docs/developer-manual/current/cypher/syntax/)

- [Common cypher confusions](https://neo4j.com/blog/common-confusions-cypher/)

#### **More Cool Tools**

- [CypherDog/DogStrike](https://github.com/SadProcessor/EmpireDog/tree/master/Modules) PowerShell Module to interact with BloodHound (& Empire) API (1.4 soon...)

- [GoFetch](https://github.com/GoFetchAD/GoFetch) Automation of lateral movement with BloodHound & Empire

- [AngryPuppy](https://www.mdsec.co.uk/2017/08/introducing-angrypuppy/) BH & CS automation by @Vysec and @Spartan



<br><br/>

<br><br/>
***

### Sample DB

Want to play with BloodHound but don't have an AD at hand? Install the supplied sample DB.

With bloodhound/neo4j stopped:

- Copy `BloodHoundExampleDB.graphdb` folder to `[...]/neo4j/data/database/`

- Open `[...]/neo4j/conf/ne4j` in text editor

- Uncomment and set db name to mount to `dbms.active_database=BloodHoundExampleDB.graphdb`

- Uncomment `#dbms.allow_upgrade=true`

- Save changes

- start neo4j/bloodhound

(you should see a graph from sample data)

- Re-comment `dbms.allow_upgrade=true` and Save change

- Done

_For automated BloodHound install script check [here](https://github.com/SadProcessor/SomeStuff/blob/master/BloodHoundw64_LTI.ps1) (windows64)_

<br><br/>

---

### KeyBoard Shortcuts

| KEY | ACTION |
| :---: | :--- |
| `CTRL` | Node **labels** ON/OFF |
| `CTRL`+`SPACE`| Node **Search** Dialog Box |
| `CRTL`+`R` | **Restart** BloodHound |
| `CTRL`+`SHIFT`+`I`| Console **Debug** |

Can use `CTRL`+`Z` and `CTRL`+`Y` in **Query Box** as kind of history function

_Note: Debuging queries is easier via neo4j browser (http://localhost:7474/Browser)_

<br><br/>

---

### UI Tweaks

:( _Made some cool ones (Dark Theme). Didn't document process. Deleted VM. Will have to try that again later..._

:) _Check out @porterhau5 in [links](#moaaar-stuff) for some awesome stuff_

<br><br/>

***

That's all I got for now. Like I said, this is just scratching the surface of Cypher queries. You can get quite funky with it (try googling for non-bloodhound cypher stuff... quite cool). I'll keep digging.

Hope this will be useful to someone somewhere. Now you can take your Dog for a walk. 




Hack the Planet...
