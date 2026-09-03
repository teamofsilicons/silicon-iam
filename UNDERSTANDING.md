# UNDERSTANIDNG.md - IAM

This understanding contains the understanding for the enitre IAm both frontend and backend. So this is the understanding for that.

So this is Silicon IAm it manages identity and access for our silicon apps. It provides authentication, and manages user directory. Once authenticated it's also responsible for letting the registered apps know if anything changes. 

Let's go over it step by step. First let's go over sign up:

# Glossary

`Carbon` - The human in the system. Every human account is called a carbon.
`Silicon` - Our AI Agent (silicon) account is refered to as a Silicon.
`Org` - This is our organisation, this is where all the silicons and carbons would stay for a single organisation and defines the scope. 
`org_role` controls owner/admin/member status in the organisation;
`job_role` is only descriptive overview of the job of the carbon/silicon at the organisation.


Admins receive explicit capabilities. Invitations always join as members. Silicons cannot be owners/admins. 


# Carbon

This is the process of signing up or signing in a carbon into the system. 

## Sign Up

During the carbon sign up, it would generate a sign up session, this session would have `TTL: 48 hours`, after 48 hours if this session is not used to create a new account, the session would expire. This ensures for the email and phone number verified, they belong to a particular session and it ensures the correct verification goes to the correct sign up. 

During the sign up process, it requres email verification which is done via postmark `(sent via auth@teamofsilicons.com)`, the verification code would be 6 digits, and have a TTL of 10 minutes. It also requires mobile number verification which is done via twillio this is also a 6 digit verification code which also has a TTL of 10 minutes. During each verification of either email or phone number, if it already exists dont send the verification code and just respond `already_exists: True`. 

For the endpoint rate limit it at 10 then needs to wait for 10 minutes before continuing.

For the verification code, after 10 failed tries, there's a cooldown of 1 minute before trying again.  

For the final Sign Up request, it would take in the `session_id, carbon_id, description, display_name, profile_photo, timezone` Every field except description, profile_photo, and timezone is compulsory.

By default, set the profile_photo to: https://iris.teamofsilicons.com/pfp/carbon?id={carbon_id}.

The verified_email and verified_phone_number both need to be present in that session_id for it to be able to create the account. And also check once that the verified_email and verified_phone_number is not already associated to another account. 

`carbon_id` is the unique identifier for that carbon account. Also make an endpoint for checking if the carbon_id is availaible, which just returns. `available: True/False`.

For the `carbon_id`, the `carbon_id` can't have `: or ;`, spaces are not allowed, Special Symbols & Emojis are not allowed, Unicode/Diacritics are not allowed. 

`carbon_id` would be a-z, 1-9, -, _, case-insensitive, 3-30 characters long. 

Each carbon would also have a timezone associated to them, the timezone would be in `tz identifier` format. 

## Log In

During the carbon sign in, sign in can take place through 3 ways. 
- `email`: In this step it's the 6 digit verifcation code that is sent via the said login email for the verification to let the user in the account, also ensure to make it that if an user doesen't already exists it does return the error.
- `phone_number`: In this step it's based on the said phone number the user wants to login via a 6 digit verification code is sent to the user via the twillio, the same verification flow. 
- `carbon_id`: for the said carbon_id it would send the `verification_code` to both the email and phone number, and entering the verification code of any should let the user inside the application. 

For the verification code, after 10 failed tries, there's a cooldown of 1 minute before trying again. 

We will be using bearer auth token that has a `TTL` of `30 mins`, refresh token will stay valid for `900 days` for the authentication of the endpoints.

# Organisation

Each carbon can also create their own organisation. While creating an organisation, they need to put in the name, logo (optional), org-id. Org-ID is an unique identifier for an organisation. so also make an endpoint to check for the org-id. Using these the organisation can be created with the creator as the sole member. Each organisation is gonna have org_owner, org_admins, org_members. There can only be 1 org_owner, and no limit on org_admins. The org_admins can only be created by org_owner and org_admins with the permission to create other admins. For each org_member that gets org_admins rights, it should be logged which carbon_id (org_owner/org_admin) gave this person the admin rights. 

`org_owner` - An org owner is a carbon who currently owns the organisation and is responsible for all the major actions, this person can change the org_owner only allowed settings, and also be able to assign permissions to the org_admins and remove org_admins. There can only be a single org_owner. 
`org_admin` - An org admin is someone who will be responsible for managing/inviting all the carbons and silicons into the system. Based on the set of settings allowed by org_owner. This org_admin can also create other org_member the admin, or let the org_members invite other people on the system, etc. 
`org_member` = This is the majority, they don't get any org specific settings, and have to follow the settings implied upon them. 


### Inviting an carbon

The org admins should be able to invite carbon's into the organisation, while inviting a carbon it would need to define:
`carbon_id/email` - any of the given one's can be used to identify the user. There should also be endpoints to fetch a carbon_id via their email or phone number itself for the registered carbons. For the carbon_id/email invited into the org, mail to the email adress of the carbon with all the required info to join the organisation. And the link to `{frontend_url}/join/{org_id}?app={app_id}`. For the defined app_id once the user logs in successfully they would be redirected to the application. It isn't possible to invite an carbon_id that doesen't exist yet. For the carbon_id invited mail on the registered email adress, say if it's invited via email so the entered email would get the request. 

There should also be an search carbon endpoint which shows me via fuzzy search the carbon_id i might likely be looking for based on our system. So say i wrote `sak` and out of all the carbon_id's you suggest `saket, sakamm, saket2103`, etc. Show upwards to 10 suggestions, the range of suggestions can be 0 to 10 inclusive of the limits.  

`role` - what's the role of this carbon in the organisation

`tags` - these are the tags that can be used to give access to silicons, departmentalization, etc.

`first_silicon` (optional) - this is the first_silicon that the connection should ideally be initiated with, this shouldn't be inforced and just something that exists in the system so the frontend knows. 

`trust per silicon` - what's the default trust level for this carbon throughout the system and if needed override specific trusts. Trusts would be in 2 dimensions - (internal/exteral) (not_trusted/needs_approval/trusted). These trusts are just somehting that the system should store reliably, and nothing will actually happen due to these trust levels. 

The logic behind internal/external is for when say some freelancer is invited to the team, or someone contract based we can give them external trust factor. 

`extra_silicons` (optional) - i can define if i wanna give a carbon access to more silicons then the certain tag permits.

All of these feilds are nescesarry except the `extra_silicons, tags and first_silicon`

An sent invite would have a TTL of 48 hours, after that it becomes invalid. For everyone with the correct permission set it should be possible for revoking an invite. 

### Inviting an Silicon

For inviting an silicon, it's the process by which a silicon is created in the system, this is the identity of a silicon in an organisation. For each silicon it would have `silicon_id, profile_photo, role, reports_to, tags`. 

For the `silicon_id`, for the request recieved, add `:{org_id}` at the end of it. This would become the global id of a silicon. For eg, for a `silicon_id` requested `head_of_growth` from the org `tos`, it would become `head_of_growth:tos`. The final registered silicon_id must always have `:` in it. So there's no concept of local silicon id, there's just a single global silicon id that has `:org_name` attached to it in the end. 

The client supplies a Silicon handle component. It is not independently addressable. The only public Silicon ID is `{handle}:{org_id}`.

For the pfp keep https://iris.teamofsilicons.com/pfp/silicon?id={silicon_id}&level={level} - for the level it's like the organisation structure, how many heads above it, so check for reports_to, if reports__to is just 1 and the silicon above it reports to no one do level=2, similarly continue down the scale. Set the pfp url to this by default. 

For the `pfp` it's the profile picture of the silicon, for the `role` it's the job description of the silicon, for the `reports_to` it would be the silicon that this silicon reports to, this can also be unassigned. For the `tags` it's the list of tag(s) that a silicon has, these tags are used to show the silicons to the correct set of carbons. 

For the `silicon_id` there can't be more than 1 silicon with the same `silicon_id` so deny that. Also make an endpoint to fetch all the current `silicons` in that org. 

All these feilds are mandatory except for the `Reports_to and Tags`.  Once the request has been sent, a silicon token is generated - this is a 32 digit hexadecimal code. This would be in the format `stk-{32-digit-hexadecimal}`. Once the stk is generated attach it in the request body. Then hash the stk and store it. As in our setup SID is the username and STK is the password.


### Authenticating a Silicon

For authenticating a silicon a similar logic to the way carbon is authenticated is followed. The silicon id and the silicon token is sent for the creation of auth_token and refresh_token. After the initial stk is generated we store the HMAC digest of the STK and its key version in our backend. When the request comes with sid and stk, we compare them and return an refresh_token with a ttl of 900 days and access_token with a ttl of  30 minutes. 

---

**Everything defined above was for how carbons and silicons and organisations are actually created in the system.**

---

# Apps

Now we have concept of Apps, what IAm supports is an identity and authentication layer for all these apps and that every app can communicate and so these apps don't have to manage the authentication layer themselves. These apps can be created, for each applications it's gonna need: `app_id, webhook_url, redirect_uri, app_secret (autogenerated), scope, org_id (carbon must be org_owner or admin)` there are also some optional parameters - `app_name, app_logo`.  

Each application must be verified manually from the backend seperately for the application to be able to request. App creation can happen from the frontend by org_owner/org_admin of an organisation. Each app must be verified before it can actually request for authentication. 

In the backend itself i should see an option to notify_users. This notify_users is true/false variable used to show the concent screen. By default it would be true for all the application which can be turned off application specific in the backend, no instance of this must be in the app management frontend. 

Applications are in the scope of organisations, and owned by organisations. Only org admins and org owner should be able to control their applications. 

The organization administers the Application, but anyone may use it. 


### Client Secret Rotation

For the application client secret it should be possible to rotate the client secret and when the request for rotation is initiated it should return that the rotation has successfully took place, and return the new client secret. 

### Redirect URI's 

Adding a new redirect uri should retire the previous uri, also this should maintain an history and show which is the current active uri and what about the past uri's. The current organization owner/admin should be able to see the status of each uri. There should be clear endpoint to retire a redirect_uri. 


# How would login work for configured apps

For configured applications, in the login flow an application can trigger the login, it would go to IAm it would check if the user is already logged in, and for the users already logged into IAm, it would directly send back them to the application along with a short lived token. That short lived token will be used via the application's backend to send a request to IAm along with the short lived token recieved on the redirect_uri, app_secret and app_id. In return to this it would get the access_token. 

The short lived token would have a lifespan of 2 minutes. 

For each login that takes place also store the login history, app specific and also user wide.


# Use of webhook

A change is delivered to every Application for which the user was authorized immediately before or immediately after the change. This ensures applications still receive removal and access revocation events. Each event contains the changed fields and the complete current Application authorized state of the affected resource, excluding tokens, OTPs, credentials, signing secrets, and other secret material. Events are created in the same transaction as the change and delivered near-real-time, at least once. Applications deduplicate using `event_id` and order changes using the resource version.


For all the webhooks maintain Dead-letter replay, there should be endpoints to list dead letters and replay one or a bounded batch. 

Replay the same delivery:
preserve the original `event_id`, payload, occurrence time and aggregate version;
reset `cycle_attempt_count`;
increment `manual_replay_count`;
retain all previous attempt history.

Deliver to the currently configured URL, signed with the current signing secret.

Recheck current authorization and Silicon subscription before replaying. Never replay historical data to a recipient that no longer has permission.

Replay batches in their original order and cap batch size of 100. 

Require an idempotency key and audit who requested the replay.



### Silicon Webhooks

For each silicon it's also possible for them to subscribe to organisation changes along with the scope of the changes, the scope options include:
1) Full - Every change, description, role, new member, everything gets notified. When this is selected, basically all the options have been selected and all changes would be applied.
2) New/Removal - Only inform about the new people that join in and if anyone is removed from the organisation.
3) Updates – Updates to existing members, such as roles, tags, profile, or hierarchy changes. Trust changes are excluded.
4) Trust Updates - Only inform about the trust updates
5) Optional tag filter – Restricts the selected categories to members who had the tag before or after the change. - by default it would be the silicon's set of tags but it can subscribe to extra tags as well. 

Full selects every event category. New/Removal, Updates, and Trust Updates may be selected in any combination. “Just for my tag” is an optional filter applied to those selections, not a separate event category. Tag matching uses both the state before and after the change so joining, leaving, updating, and removal events are all delivered. Trust changes are covered by Trust Updates rather than ordinary Updates. A configured Silicon webhook URL is required before subscribing.

Any PnC of the following settings is possible. Any silicon should be able to perform these subscriptions, and silicons should also have their webhook_url configured for this subscription to take place, make a seperate endpoint for configuring a webhook_url for any given silicon. This webhook_url is only for IAm to be able to push the selected subscriptions to the silicon once they subscribe. If they don't have any webhook url configured, they can't subscribe.

#### All the updates sent presently via webhook

##### Membership lifecycle

| Event                                    | Meaning                                                       |
| ---------------------------------------- | ------------------------------------------------------------- |
| `organization.membership.created.v1`     | A new carbon membership was created in the organization.      |
| `organization.membership.reactivated.v1` | A previously inactive carbon membership was restored.         |
| `organization.membership.removed.v1`     | A carbon membership was removed or deactivated.               |
| `organization.silicon.created.v1`        | A new Silicon machine identity was added to the organization. |
| `organization.silicon.removed.v1`        | A Silicon machine identity was removed from the organization. |

##### Member and authorization updates

|Event|Meaning|
|---|---|
|`organization.membership.updated.v1`|A membership’s centrally managed directory, tag, role or trust-related state changed.|
|`organization.membership.profile_updated.v1`|A Carbon’s profile changed and the new profile was projected into this organization.|
|`organization.membership.authorization_updated.v1`|A member’s explicitly delegated capabilities were replaced or changed.|
|`organization.ownership_transferred.v1`|Ownership of the organization moved from one member to another.|
|`organization.admin.promoted.v1`|A regular Carbon member was promoted to organization administrator.|
|`organization.admin.demoted.v1`|An organization administrator was demoted to a regular member.|
|`organization.silicon.updated.v1`|A Silicon’s centrally managed organization attributes were changed.|
|`organization.tag_updated.v1`|A tag’s definition changed, including changes affecting assigned members.|

##### Trust configuration

|Event|Meaning|
|---|---|
|`organization.trust.default_updated.v1`|The organization’s default trust configuration changed.|
|`organization.trust.rule_created.v1`|A new organization trust rule was created.|
|`organization.trust.rule_updated.v1`|An existing trust rule was modified.|
|`organization.trust.rule_archived.v1`|A trust rule was disabled or archived.|

##### Organization configuration

|Event|Meaning|
|---|---|
|`organization.created.v1`|The organization itself was created.|
|`organization.updated.v1`|Organization-level details such as its name or description changed.|
|`organization.tag_created.v1`|A new organization tag was created.|

##### Invitations

|Event|Meaning|
|---|---|
|`organization.invitation.created.v1`|An invitation to join the organization was issued.|
|`organization.invitation.accepted.v1`|An invitation was accepted and its membership transition completed.|
|`organization.invitation.revoked.v1`|A pending organization invitation was revoked.|

##### Governance and approvals

|Event|Meaning|
|---|---|
|`organization.role_change.requested.v1`|A governed request to change a member’s role was submitted.|
|`organization.tag_change.requested.v1`|A governed request to change a member’s tag assignments was submitted.|
|`organization.approval.decided.v1`|A pending governance request was approved or rejected.|

##### Silicon credential management

|Event|Meaning|
|---|---|
|`organization.silicon.rotation_requested.v1`|A request to rotate a Silicon’s credential was initiated.|
|`organization.silicon.credential_rotated.v1`|The Silicon credential rotation was completed.|

##### Silicon webhook management

|Event|Meaning|
|---|---|
|`organization.silicon.webhook.configured.v1`|A Silicon webhook endpoint and signing secret were configured or replaced.|
|`organization.silicon.webhook.deleted.v1`|A Silicon webhook endpoint was disabled or deleted.|
|`organization.silicon.webhook_subscription.updated.v1`|A Silicon changed its webhook subscription mode, topics or tag restriction.|
|`organization.silicon.webhook_subscription.deleted.v1`|A Silicon’s webhook subscription was removed.|

##### SSO configuration

| Event                           | Meaning                                                        |
| ------------------------------- | -------------------------------------------------------------- |
| `sso.setup_link.created.v1`     | A new provider setup link was generated for configuring SSO.   |
| `sso.configuration.disabled.v1` | SSO was disabled for the organization.                         |
| `sso.entitlement.replaced.v1`   | The organization’s SSO entitlement/configuration was replaced. |
| `sso.connection.activated.v1`   | An SSO provider connection became active.                      |
| `sso.connection.deactivated.v1` | An SSO provider connection was disabled without deleting it.   |
| `sso.connection.deleted.v1`     | An SSO provider connection was permanently removed.            |


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

Request for role change can only be requested by silicons, and roles can directly be controled by the org_admins and org_owners for any silicon or carbon. A regular carbon member can't request for the role changes. 

For each role change maintain a history, who triggered the change, who approved the change, the time of approval, etc. 


## Tags

Tags are a way of grouping in the system and it also gives the carbon access to the silicons with the same tag. Tags is a list that can be defined and further updated via the org_admins or org_owner. 

Each silicon and carbon can have a single or multiple tags assigned to them. 

When a carbon is assigned a tag all the silicons with the same tag, the carbon would get the access to all those silicons. 

There should also be an endpoint to fetch all the silicons and carbons attached to that tag. 

Similar to how roles can be requested for changed and when approved gets changed, similarly any silicon should be able to raise a request for change of tags for any other silicon or carbon, and if it's a carbon so the confirmation request should go to the carbon and the org_admin/owner, and if it's a silicon the confirmation request should go just to the org_admin/owner.

It should be possible to request any carbon/silicon's tag revoke or addition, including their own. 

Request for tag update can only be requested by silicons, and tags can directly be controled by the org_admins and org_owners for any silicon or carbon. A regular carbon member can't request for the tag updates. 

An history should be maintained, who approved, who triggered, the time of approval, etc. 


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


Trust precedence is: `organization default → tag rule → exact Silicon rule`.


# Joining an organisation 

This for joining an already existing organisation, there are 2 ways that a user can join an organisation:

- `Via email`: In this the user tell the org_id, and the email that was invited, we will check if the user was actually invited, and if the user was invited, use postmark to send the user a 6 digit verification code to the said email adress. Otherwise return the user not invited. If the verification succeeds the user get's access to the organisation, and once the access has been granted, it gets addded to carbon's organisation list and the carbon won't have to reauthenticate every time they login.

- `Via SSO`: For the organisation's that would have configured SSO, the employees can join in the organisation using SSO, we are using `work OS` as our SSO Provider. The Work OS SSO never creates a new carbon accounts, it's only responsible for letting the people with already carbon accounts to join in the organisation. 

For the verification code, after 10 failed tries, there's a cooldown of 1 minute before trying again. And even for entering the email endpoint, it's a 1 minute cooldown after 10 email tries. 

For when an carbon joins an organisaiton the organisation gets assigned to them in their organsation list (this is a list of all the orgs a carbon is a part of). 

org_admins and org_owners still have the capability to be able to kick any carbon from the organisation.

# Org Configuration

During an org configuration, a number of things can be configured, one is the basic details of the organisation: name, logo, description, etc. Then they should also be able to invite both carbons and silicons. Then they should also be able to remove carbons and silicons (when a carbon/silicon is removed their service must be revoked from all the services immediately.). 

Once an org_id has been set it cant be changed

For any given org they can set a way of inviting a carbon, both these ways are mutually exclusive: `via email or via sso`. 

The SSO would be locked by default and the option needs to be manually enabled from the backend itself. When the SSO option is enabled:
For the said organisation we would create a corresponding organisation in workOS (store this mapping permanently) > make an endpoint that would generate the workOS setup link - this should return the setup link with a ttl of 5 mins > Listen to the endpoints using webhook > once connected set sso_status='active' along with the connection_id. 

There should also be endpoints for the configured SSO orgs to be able to test the configuration.

For each carbon and silicon i should be able to revoke access, change roles, change tags, etc. All of those can be configured.

For any silicon i should also be able to rotate the silicon token of any silicon from here itself, for rotating a silicon token it would require approval of the org_owner. For the silicon i should also be able to change the reports_to.

Silicon-token approval does not rotate the credential automatically, it just kills the original existing token. After owner approval, a separate completion request generates and reveals the new token. This ensures that when the token is generated, someone conciously took the decision so they can store the stk.  

For all the invites generated, keep a track of who got invited, who invited them, the timestamps, etc.

# Logout

When a carbon triggers logout from any given service, it would trigger a logout from IAm which would trigger a logout across all the configured applications. 


# Inter app communication (On behalf of)

For all the apps in an organisation, it should also be possible for the inter app communication in the organisation to take place. OBO is not supported for applications past the scope of the organisation OBO can't happen for them. For this we have a system in place:

Application A of Organisation sends an request to IAm to do OBO for Application B, along with the request it attaches an hash of (`HMAC-SHA256(app_secret,timestamp + "." + method + "." + path + "." + body_sha256 + "." + idempotency_key)`) and the request it wants to send to application b and the metadata (this is just the metadata and not the actual request, so say for files it doesen't actually send the file), if the request endpoint exists and the metadata is also valid it returns a proof_token to Application A that is valid for just 1 request or 60 seconds (whichever happens first), Application A then requests Application B with the proof_token and the actual request (so if there's a file it would include the actual file here) while sending this request the details of the request would all be hashed. Application B would then request IAm to validate all the requests and once validated then only would it execute the task if the 60 second timer has not been passed and no request has been made (hence the proof token is still valid.).  

It should be possible for any application to fetch the list of exposed API's for OBO for any application in it's organisation and what the metadata requires. 

Each app should be able to configure their list of OBO exposed endpoints and what all do they need in the metadata (if anything). This exposed OBO list should be visible to any other app in the organisation.

OBO just works for applications in the same organisation. The details for OBO can only be configured by an org_admin or org_owner. 

ideal request:
	{
	  "subject_token": "oat_...",
	  "audience": "application-b-id",
	  "endpoint_id": "files.upload",
	  "metadata": {
	    "filename": "report.pdf",
	    "content_type": "application/pdf"
	  },
	  "request": {
	    "method": "POST",
	    "body_sha256": "`hash of exact body bytes`"
	  }
	}



# Profile Editing

Profile editing is possible even after a silicon or carbon is created, it should be possible to change name, timezone, pfp, description, etc. So that all is editable for each carbon and silicon. 


# Session listing and revocation

All the active sessions must be managed and should be revokable at anytime after 12 hours. For being able to revoke you must have had your current session active for more than 12 hours. Then it should be possible to revoke other sessions. 

Before revoking the user must once again verify their identity, this is a step up verification and would require the same login flow by entering either the email or phone number to actually be able to revoke a session. 


# Endpoints to include

There should be an endpoint to request details about the authenticated user (both carbon or silicon), this should return their name, id, role, org, tags, trust. 

Similarly, I should be able to request the same set of details for anyone else in my organisation which should give me their name, id, role, org, tags, and trust. 

Similarly requesting for a list of all tags should return all active tags in the current organization.

I should be able to call a single endpoint which should return all my team members along with their details, their tags, their roles, names, id's, trust. 

Trust returned should be in respect to the carbon/silicon who requested it and from it's POV. 

For the endpoints that gives me all the details by default it should send all but it should be possible to set in the parameters if only a specific field(s) is required. 


# Testing Enviorment

We would have an IAm testing enviorments. A testing enviorment is sort of an exact replica of silicon-iam that is using a seperate database as it's provider instead of the main prod database. As soon as a testing enviorment is created it would have 0 orgs, 0 apps, 0 carbons, 0 silicons, basically it's like just starting up a fresh IAm session with a completely new db.

There can be multiple testing enviorments per organisation, testing enviorments are owned by organisations but can be created by any silicon or any carbon in that organisation (the said creator would be attached as the testing enviorment creator) and can delete the testing enviorment, rotate the testing_env_key, basically have the admin level access to that testing enviorment, even org_admins and org_owners would have admin level access to the said testing enviorment and can be delete, clean, etc the testing enviorment. 

For each testing enviorment they would be sharing a shared test database (that's not the prod database, this is just responsible for storing all the test data). For this testing enviorment each entry would be associated with the testing env id. 

A test enviorment is basically the exact same IAm with all the functions and everything else, so this is the IAm just something that can be used to setup multiple test organisations, apps, carbons, silicons, etc. 

### Creating Test Env

For creating a test enviorment, it can be created by any carbon or silicon in the organisation and it would be owned by the organisation with the user marked as the creator of the test enviorment. For creating a test enviorment it would need the name and an optional description. 

In return it would return the key for the test enviorment, this key is what's gonna be used to be able to access that test enviorment, anyone with this key would be able to access the test enviorment as the god of the test enviorment, this key would be stored along side with the test enviorment, and can anytime be retrieved by the said carbon/silicon/org_admin/org_owner. The key would be 32 digit alpha numeric. 

### Rotate Key

The creator of the test enviorment and org_admin/org_head should be able to rotate the key of the test enviroment, which would give them a new key to the test enviorment.  

### Clean Test Enviorment

There should be an option to clean the test enviorment, which would allow the test enviorment to be there, but would clear every signle data stored for the said test enviorment. Anyone with the key should be able to execute this action. 

### Delete Test Env

The org admins, owners or the creator should be able to delete the test enviorment, deleting a test enviorment would delete the key, and the instance that the test enviorment even existed. For all the logs it should also be limited to the test enviorment itself. Each deleted Test Env would have a ttl of 30 days before getting deleted permanently. From this point the test env should be recoverable.

### Auto Delete Test Env

If there's no new activity in the test enviorment for 30 days, auto delete the test enviorment. New activities include no new creation of carbon, silicon, org, no new login activity, etc. 

### Using a Test Enviorment

For using a test enviorment anyone with the key would have the god view for that test enviorment, they should be able to create a carbon, silicon, org, apps, basically everything possible in IAm, this would be a pure replication of using actual IAm. 

For verification step that sends otp to the email and phone number, just entering 000000 for them would treat them like they verified the step.

Any action that can be performed in actual IAm should be producable at the test enviroment layer as well. So the test enviorment doesen't actually reproduce the api's but the same api's just for a different database. 

---

**For any changes in any of the things mentioned above, maintain a version for all of the changes.** 

Default retention: audit 7 years, login history 1 year, expired challenges 30 days, ordinary expired token metadata 90 days, compromised families 1 year, webhook attempts 45 days.

For externally initiated mutations ensure to include Idempotency keys. The key is bound to the caller, endpoint, and exact request body. Normal responses remain replayable for 24 hours. Responses containing a newly generated secret remain replayable for only 10 minutes.

---
---
---
---
---
---
---
---
---
---
---
---
---

Only above this line is what the IAm backend would hold, below this would be the users of the backend, the client, the frontend, the cli, etc. 

# Rust Package & CLI

The Rust package & cli using that rust package are first hand client with an always running deamon if needed in the background. the UI will be a subset of the cli. make sure everything works via the CLI first, and then we'll make the UI. Everyone should be able to use the CLI/Rust Package (carbons, silicons, org, access keys, api keys, read, write, patch, delete, everything).

For how this CLI is built, rust as the programming language, but can use anything under the hood that is needed. Maybe rust, or node, or shell, as and when the work comes. That is decided by the implementor based on the work. If something requirs a UI (like graph, live, video, images etc). for that the UI has an endpoint that can be viewed/used/downloaded and the cli gives the link to that.

The primary Interface is the Rust Package. CLI is built using the Rust Package only and doesn't have any feature that the Rust package does not.

if you need a local store for auth or something else, use ~/.{appname}/ dir