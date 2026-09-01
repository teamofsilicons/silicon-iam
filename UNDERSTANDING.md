# UNDERSTANIDNG.md - IAM

This understanding contains the understanding for the enitre IAm both frontend and backend. So this is the understanding for that.

So this is Silicon IAm it manages identity and access for our silicon apps. It provides authentication, and manages user directory. Once authenticated it's also responsible for letting the registered apps know if anything changes. 

Let's go over it step by step. First let's go over sign up:

# Glossary

`Carbon` - The human in the system. Every human account is called a carbon.
`Silicon` - Our AI Agent (silicon) account is refered to as a Silicon.
`Org` - This is our organisation, this is where all the silicons and carbons would stay for a single organisation and defines the scope. 


# Carbon

This is the process of signing up or signing in a carbon into the system.

## Sign Up

During the carbon sign up, it would generate a sign up session, this session would have `TTL: 48 hours`, after 48 hours if this session is not used to create a new account, the session would expire. This ensures for the email and phone number verified, they belong to a particular session and it ensures the correct verification goes to the correct sign up. 

During the sign up process, it requres email verification which is done via postmark `(sent via auth@teamofsilicons.com)`, the verification code would be 6 digits, and have a TTL of 10 minutes. It also requires mobile number verification which is done via twillio this is also a 6 digit verification code which also has a TTL of 10 minutes. During each verification of either email or phone number, if it already exists dont send the verification code and just respond `already_exists: True`. 

For the endpoint rate limit it at 10 then needs to wait for 10 minutes before continuing.

For the verification code, after 10 failed tries, there's a cooldown of 1 minute before trying again.  

For the final Sign Up request, it would take in the `session_id, carbon_id, description, display_name, profile_photo` Every field except description or profile_photo is compulsory.

By default, set the profile_photo to: https://iris.teamofsilicons.com/pfp/carbon?id={carbon_id}.

The verified_email and verified_phone_number both need to be present in that session_id for it to be able to create the account. And also check once that the verified_email and verified_phone_number is not already associated to another account. 

`carbon_id` is the unique identifier for that carbon account. Also make an endpoint for checking if the carbon_id is availaible, which just returns. `available: True/False`.

For the `carbon_id`, the `carbon_id` can't have `: or ;`, spaces are not allowed, Special Symbols & Emojis are not allowed, Unicode/Diacritics are not allowed. 

`carbon_id` would be a-z, 1-9, -, _, case-insensitive, 3-30 characters long. 

## Log In

During the carbon sign in, sign in can take place through 3 ways. 
- `email`: In this step it's the 6 digit verifcation code that is sent via the said login email for the verification to let the user in the account, also ensure to make it that if an user doesen't already exists it does return the error.
- `phone_number`: In this step it's based on the said phone number the user wants to login via a 6 digit verification code is sent to the user via the twillio, the same verification flow. 
- `carbon_id`: for the said carbon_id it would send the `verification_code` to both the email and phone number, and entering the verification code of any should let the user inside the application. 

For the verification code, after 10 failed tries, there's a cooldown of 1 minute before trying again. 

We will be using bearer auth token that has a `TTL` of `365 days` for the authentication of the endpoints. 

# Organisation

Each carbon can also create their own organisation. While creating an organisation, they need to put in the name, logo, org-id. Org-ID is an unique identifier for an organisation. so also make an endpoint to check for the org-id. Using these the organisation can be created with the creator as the sole member. Each organisation is gonna have org_owner, org_admins, org_members. There can only be 1 org_owner, and no limit on org_admins. The org_admins can only be created by org_owner and org_admins with the permission to create other admins. For each org_member that gets org_admins rights, it should be logged which carbon_id (org_owner/org_admin) gave this person the admin rights. 

`org_owner` - An org owner is a carbon who currently owns the organisation and is responsible for all the major actions, this person can change the org_owner only allowed settings, and also be able to assign permissions to the org_admins and remove org_admins. There can only be a single org_owner. 
`org_admin` - An org admin is someone who will be responsible for managing/inviting all the carbons and silicons into the system. Based on the set of settings allowed by org_owner. This org_admin can also create other org_member the admin, or let the org_members invite other people on the system, etc. 
`org_member` = This is the majority, they don't get any org specific settings, and have to follow the settings implied upon them. 


### Inviting an carbon

The org admins should be able to invite carbon's into the organisation, while inviting a carbon it would need to define:
`carbon_id/email` - any of the given one's can be used to identify the user. There should also be endpoints to fetch a carbon_id via their email or phone number itself for the registered carbons. For the carbon_id/email invited into the org, mail to the email adress of the carbon with all the required info to join the organisation. And the link to `{frontend_url}/join/{org_id}?app={app_id}`. For the defined app_id once the user logs in successfully they would be redirected to the application. It isn't possible to invite an carbon_id that doesen't exist yet. For the carbon_id invited mail on the registered email adress, say if it's invited via email so the entered email would get the request. 

There should also be an search carbon endpoint which shows me via fuzzy search the carbon_id i might likely be looking for based on our system. So say i wrote `sak` and out of all the carbon_id's you suggest `saket, sakamm, saket2103`, etc. Show upwards to 10 suggestions, the range of suggestions can be 0 to 10 inclusive of the limits.  

`role` - what's the role of this carbon in the organisation

`tags` - these are the tags that can be used to give access to silicons, departmentalization, etc.

`first_silicon` - this is the first_silicon that the connection should ideally be initiated with, this shouldn't be inforced and just something that exists in the system so the frontend knows. 

`trust per silicon` - what's the default trust level for this carbon throughout the system and if needed override specific trusts. Trusts would be in 2 dimensions - (internal/exteral) (not_trusted/needs_approval/trusted). These trusts are just somehting that the system should store reliably, and nothing will actually happen due to these trust levels. 

The logic behind internal/external is for when say some freelancer is invited to the team, or someone contract based we can give them external trust factor. 

`extra_silicons` - i can define if i wanna give a carbon access to more silicons then the certain tag permits.

All of these feilds are nescesarry except the `extra_silicons, tags`

An sent invite would have a TTL of 48 hours, after that it becomes invalid. For everyone with the correct permission set it should be possible for revoking an invite. 

### Inviting an Silicon

For inviting an silicon, it's the process by which a silicon is created in the system, this is the identity of a silicon in an organisation. For each silicon it would have `silicon_id, profile_photo, role, reports_to, tags`. 

For the `silicon_id`, for the request recieved, add `:{org_id}` at the end of it. THis would become the global id of a silicon. For eg, for a `silicon_id` requested `head_of_growth` from the org `tos`, it would become `head_of_growth:tos`. The final registered silicon_id must always have `:` in it. 

For the pfp keep https://iris.teamofsilicons.com/pfp/silicon?id={silicon_id}&level={level} - for the level it's like the organisation structure, how many heads above it, so check for reports_to, if reports__to is just 1 and the silicon above it reports to no one do level=2, similarly continue down the scale. 

For the `pfp` it's the profile picture of the silicon, for the `role` it's the job description of the silicon, for the `reports_to` it would be the silicon that this silicon reports to, this can also be unassigned. For the `tags` it's the list of tag(s) that a silicon has, these tags are used to show the silicons to the correct set of carbons. 

For the `silicon_id` there can't be more than 1 silicon with the same `silicon_id` so deny that. Also make an endpoint to fetch all the current `silicons` in that org. 


All these feilds are mandatory except for the `Reports_to and Tags`.  Once the request has been sent, a silicon token is generated - this is a 16 digit hexadecimal code. This would be in the format `stk-{16-digit-hexadecimal}`. Once the stk is generated attach it in the request body. Then hash the stk and store it. As in our setup SID is the username and STK is the password.

  

### Authenticating a Silicon

For authenticating a silicon a similar logic to the way carbon is authenticated is followed. The silicon id and the silicon token is sent for the creating the auth_token. We will do `SID+STK+Salt` to create an auth token. This auth_token would be used by the silicon accounts to perform any silicon actions. It should be possible to rotate both the Salt and the STK. The STK rotation can be requested by the org_owner. Salt rotation doesen't have any public endpoints.

---

**Everything defined above was for how carbons and silicons and organisations are actually created in the system.**

# Apps

Now we have concept of Apps, what IAm supports is an identity and authentication layer for all these apps and that every app can communicate and so these apps don't have to manage the authentication layer themselves. These apps can be created, for each applications it's gonna need: `app_id, webhook_url, redirect_uri, app_secret (autogenerated), scope` there are also some optional parameters - `app_name, app_logo`.  

Each application must be verified manually from the backend seperately for the application to be able to request. App creation can happen from the frontend by any user. Each app must be verified before it can actually request for authentication. 

In the backend itself i should see an option to notify_users. This notify_users is true/false variable used to show the concent screen. By default it would be true for all the application which can be turned off application specific in the backend, no instance of this must be in the app management frontend. 


# How would login work for configured apps

For configured applications, in the login flow an application can trigger the login, it would go to IAm it would check if the user is already logged in, and for the users already logged into IAm, it would directly send back them to the application along with a short lived token. That short lived token will be used via the application's backend to send a request to IAm along with the short lived token recieved on the redirect_uri, app_secret and app_id. In return to this it would get the access_token. 

The short lived token would have a lifespan of 2 minutes. 

For each login that takes place also store the login history, app specific and also user wide.


# Use of webhook

For each application's defined webhook url, for any changes in user it should be communicated over to all the applications through the said webhook url. These updates would include anything/everything that the IAm stores regarding that user, so say if a user is kicked from an organisation it should be communicated over via webhook almost instantly. If someone's role changed, if someone's pfp changed, basically any changes that happen that are centerally managed by IAm it should be communicated over using the said webhook connection. For all the application's that the user's current auth token is valid in. 


### Silicon Webhooks

For each silicon it's also possible for them to subscribe to organisation changes along with the scope of the changes, the scope options include:
1) Full - Every change, description, role, new member, everything gets notified. When this is selected, basically all the options have been selected and all changes would be applied.
2) New/Removal - Only inform about the new people that join in and if anyone is removed from the organisation.
3) Updates - Only inform about the updates of already existing members. Like role update, tags update, trust update, etc
4) Trust Updates - Only inform about the trust updates
5) Just for my tag - Only inform me about the selected changes if they are of my tag, if a new peoson joins my tag, or gets removed, gets their roles updated, etc.

Any PnC of the following settings is possible. Any silicon should be able to perform these subscriptions, and silicons should also have their webhook_url configured for this subscription to take place, make a seperate endpoint for configuring a webhook_url for any given silicon. This webhook_url is only for IAm to be able to push the selected subscriptions to the silicon once they subscribe. If they don't have any webhook url configured, they can't subscribe.

# Organisation specifications stored in IAm

IAm would serve as the authentication and authorization layer for all the organisations. It would also serve as the centeral directory control for all the organisations. If a member has been removed from an organisation here, they would be kicked from that organisation in every single tool and would lose access to them all. 

For each organisation it would have some organisation centered settings and configurations and would also have member specific things. 

## Carbons

For each carbon in an organisation they would have a role (a job description), tags (acts as a classifier that can be used), first_silicon (this is the first silicon any carbon would interact with), trust/silicon (trust can be configured, there would be a default trust organisation wide, and also i can overwrite trust for specific tags and also specific silicons.), Extra silicons (a carbon when getting invited would get access to a set of silicons, they can also be given access to extra silicons during invite or even after invite, these are extra silicons except the silicons the user already has access to).


## Silicons

For each silicon, silicon can and will only be created org specific, there would be a role defined to a silicon, their reports_to - this is the silicon they are responsible to and must report, and tags are just a way of categorizing silicons. For a tag if the same tag is given to a carbon they will get access to this silicon. 


## Role

Role is a description of what a carbon/silicon job is, these could be a maximum of 5000 characters. Both carbon's and silicon's would have roles, for each role of either silicon/carbon can change it, a silicon can also change it's own or other silicons and carbons roles and similarly a carbon can change other silicons roles, a carbon wouldn't be able to change another carbons role. Only org_admins, org_owner and silicons would have the right to change a carbon's role.

For each carbon role change a request of approval would go both to the affected carbon and the org_admin/org_owner . When both of them approve the change is when the change actually gets approved and the role of that carbon is changed.

For change in any silicon's role an approval request would go just to the org_admin/org_owner. When they approve the role change, it would be reflected.  

Roles of each carbon and silicon can be access by any another carbon and silicon in the same organisation.

For each role change maintain a history, who triggered the change, who approved the change, the time of approval, etc. 


## Tags

Tags are a way of grouping in the system and it also gives the carbon access to the silicons with the same tag. Tags is a list that can be defined and further updated via the org_admins or org_owner. 

Each silicon and carbon can have a single or multiple tags assigned to them. 

When a carbon is assigned a tag all the silicons with the same tag, the carbon would get the access to all those silicons. 

There should also be an endpoint to fetch all the silicons and carbons attached to that tag. 


## Trust

Trusts are gonna be on 2 dimensions:
one is - external or internal 
and another is - not trusted or needs approval or trusted

For carbons i could assign the carbon a trust based on their tag, for example for all the silicons in tech tag they are internal and trusted, but for any other silicon they are internal and not trusted.  

or it could be silicon specifc, in tech tag they are internal and trusted, but internal and needs approval for tech-deployment-silicon:tos. 

by default keep it internal and not trusted. 



For inter silicon trust, it would have inter tag trust, so it would create a sort of matrix. For eg: there are 5 tags: Tech, Law, Growth, Finance

Now there a matrix created
How much does tech trust tech, tech trust law, tech trust growth, tech trust finance. Similarly for each department, so this creates both way trust, how much does a silicon in finance trust silicon in tech and how much does a silicon in tech trust silicon in finance. So this kind of matrix will be defined for it.


# Joining an organisation 

This for joining an already existing organisation, there are 2 ways that a user can join an organisation:

- `Via email`: In this the user tell the org_id, and the email that was invited, we will check if the user was actually invited, and if the user was invited, use postmark to send the user a 6 digit verification code to the said email adress. Otherwise return the user not invited. If the verification succeeds the user get's access to the organisation, and once the access has been granted, it gets addded to carbon's organisation list and the carbon won't have to reauthenticate every time they login.

- `Via SSO`: For the organisation's that would have configured SSO, the employees can join in the organisation using SSO, we are using `work OS` as our SSO Provider. 

For the verification code, after 10 failed tries, there's a cooldown of 1 minute before trying again. And even for entering the email endpoint, it's a 1 minute cooldown after 10 email tries. 

For when an carbon joins an organisaiton the organisation gets assigned to them in their organsation list (this is a list of all the orgs a carbon is a part of). 

org_admins and org_owners still have the capability to be able to kick any carbon from the organisation.

# Org Configuration

During an org configuration, a number of things can be configured, one is the basic details of the organisation: name, logo, description, etc. Then they should also be able to invite both carbons and silicons. Then they should also be able to remove carbons and silicons (when a carbon/silicon is removed their service must be revoked from all the services immediately.). 

Once an org_id has been set it cant be changed

For any given org they can set a way of inviting a carbon, both these ways are mutually exclusive: `via email or via sso`. 

The SSO would be locked by default and the option needs to be manually enabled from the backend itself. When the SSO option is enabled:
For the said organisation we would create a corresponding organisation in workOS (store this mapping permanently) > make an endpoint that would generate the workOS setup link - this should return the setup link with a TTL of 2 hours > Listen to the endpoints using webhook > once connected set sso_status='active' along with the connection_id. 

There should also be endpoints for the configured SSO orgs to be able to test the configuration.

For each carbon and silicon i should be able to revoke access, change roles, change tags, etc. All of those can be configured.

For any silicon i should also be able to rotate the silicon token of any silicon from here itself, for rotating a silicon token it would require approval of the org_owner. For the silicon i should also be able to change the reports_to.

For all the invites generated, keep a track of who got invited, who invited them, the timestamps, etc.

# Logout

When a carbon triggers logout from any given service, it would trigger a logout from IAm which would trigger a logout across all the configured applications. 


# Inter app communication

For all the apps in the system, it should also be possible for the inter app communication to take place. For this we have a system in place:

Let's call them app a, and app b for this example.

Let's say App A wants to perform an action on App B as Carbon C (common across both apps). 
App A contacts App B with it's app_id, and a hashed (auth_token of the carbon c + app a secret) this would be hashed and called proof_token, this goes to app b, it calls IAm asks it to verify this proof, it also hashes the (app_secret and auth_token of carbon c on that app) and compares it to the provided hash. If those 2 match then it's a valid request and App A would be able to perfom actions on App B as the Carbon C.  

---

**For any changes in any of the things mentioned above, maintain a version for all of the changes. The number can differ based on the importance of the said task.** 


---

# Frontend

Our frontend is gonna support the login/signup layer and also the layer where all the apps can be managed and configured, also the backend should have a webpage where it's easy to see all the apps configured and be able to remove apps, allow/disallow some specific actions as defined, etc.

## Login

For the login flow keep the email/carbon id page first, and then a textual button option below that to Use Phone Number instead. For devices below 1000px width keep the default option to phone number and use Email/Carbon ID instead as the secondary option. 

For the phone number also keep a country code picker, by default set it based on the user's ip location. 

For the 6 digit verification code input, it should be an OTP input. 

## Signup 

For the signup flow, first ask the user for their email, then verify email, then their phone number, then verify phone, then carbon_id picker, then a basic profile config page.

## App Defining

When a user has signed up onto Silicon IAm they can create an application, using the details specified. Then as soon as an application request has been sent, display that the application is under review. 

# Org

Org Creation and joining will also be handled via the frontend itself where they will see all the steps to create an organisation and also when someone's joining so join the organisation. 

I should also be able to invite people into my organisation using the same login. 

## Backend User Interface

For the backend UI would want to see all the app's not reviewed as of now, enable/disable all the settings. Delete an application, etc. And all such changes must also be displayed in the base IAm profile. 

---

# Design Style to follow

Keep the entire design minimal, the website is gonna be light mode, #fffff with #1a1a1a text. 
The main acent: #2B4CF2 . Gradient and other colors to use: 76D4F0, F9F987, FEAD75, F15347, 14245F. 

For the overall design flow think what's the best possible style to show this information, how can i make this design look extraordianry. Attached a few images to use as our design taste. 

https://ibb.co/d4H9L6z5
https://ibb.co/mFMpGzt4
https://ibb.co/Y4FYS5F1
https://ibb.co/8ny7Vnks
https://ibb.co/q3R69c2H
https://ibb.co/21bmvdc3
https://ibb.co/vvf7gyjQ
https://ibb.co/ZpQqCWZz
https://ibb.co/d0nG1BWK

## Typography

Body + headings: Crimson Pro. Body 17-18px, line-height 1.6, measure 60-70 characters. - Headings: same serif, 40-52px, weight 400-500, line-height 1.15, full sentences ending in a period. - Labels/eyebrows/captions: Inter. 10-11px, UPPERCASE, letter-spacing 0.08em only. - Section numbers: sans, 32-40px, accent colour, paired with a small uppercase label on the same baseline. - Never mix the two roles: serif is never uppercase-letterspaced, sans is never large.

# Links

backend.iam.teamofsilicons.com - the link where the backend would be hosted.
backend.iam.teamofsilicons.com/admin - this is the admin page where the backend ui would be displayed
iam.teamofsilicons.com - this is the main iam page where the apps would be created
auth.iam.teamofsilicons.com - this is the page where the login/signup would actually take place
