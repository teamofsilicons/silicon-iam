
# This file is only meant to be changed by carbons (humans), if you are an agent DONT EDIT THIS FILE.  


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

During the sign up process, it requres email verification which is done via postmark `(sent via iam@teamofsilicons.com)`, the verification code would be 6 digits, and have a TTL of 10 minutes. It also requires mobile number verification which is done via twillio this is also a 6 digit verification code which also has a TTL of 10 minutes. During each verification of either email or phone number, if it already exists dont send the verification code and just respond `already_exists: True`. 

For the endpoint rate limit it at 10 then needs to wait for 10 minutes before continuing.

For the verification code, after 10 failed tries, there's a cooldown of 1 minute before trying again.  

For the final Sign Up request, it would take in the `session_id, carbon_id, description, display_name, profile_photo, timezone` Every field except description, profile_photo, and timezone is compulsory.

By default, set the profile_photo to: https://iris.teamofsilicons.com/pfp/carbon?id={carbon_id}.

The verified_email and verified_phone_number both need to be present in that session_id for it to be able to create the account. And also check once that the verified_email and verified_phone_number is not already associated to another account. 

`carbon_id` is the unique identifier for that carbon account. Also make an endpoint for checking if the carbon_id is availaible, which just returns. `available: True/False`.

For the `carbon_id`, the `carbon_id` can't have `: or ; or >`, spaces are not allowed, Special Symbols & Emojis are not allowed, Unicode/Diacritics are not allowed. 

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


For when an org_admin is created by default they have all the rights except the right to be able to create/remove other org admins.


### Inviting an carbon

The org admins should be able to invite carbon's into the organisation, while inviting a carbon it would need to define:
`carbon_id/email` - any of the given one's can be used to identify the user. There should also be endpoints to fetch a carbon_id via their email or phone number itself for the registered carbons. For the carbon_id/email invited into the org, mail to the email adress of the carbon with all the required info to join the organisation. And the link to `{frontend_url}/join/{org_id}`. It isn't possible to invite an carbon_id that doesen't exist yet. For the carbon_id invited mail on the registered email adress, say if it's invited via email so the entered email would get the request. 

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

For each application, IAM provides identity, authentication and authorization. Application configuration comes from Honeycomb; IAM validates it and maintains the accepted authentication record.

IAM keeps app_id, org_id, app_name and app_logo used during login, webhook_url, the protected webhook signing secret, webhook_scope, base_url, requested and effective app_scope, OBO definitions and the application's accepted availability and private/public status. IAM generates the app_secret, stores its verification hash and returns the secret only through the protected creation response for the authorized owner. Base_url is optional unless the application exposes OBO endpoints.

The app_id is always org_id>local_app_id, so for eg tos>briefcase. Use the organisation's ID, not its display name. The app_id and owning organisation cannot be changed through a configuration update. Organisations own their apps; the creator is recorded for audit and does not retain separate ownership.

Webhook_scope selects which authorized notification categories the application receives. It is separate from the permissions requested during login.

IAM owns its permission catalog, trusted-organisation scope eligibility, validation of provider approvals, effective scopes and user consent. Expose the catalog with descriptions, critical flags and reviewer requirements. Validate incoming scope changes and decisions, and enforce accepted scopes during login, API access, webhooks and OBO.

For an Application, its owning organisation's current Carbon org_owner or org_admin can approve a pending webhook destination through Honeycomb, including the first pending webhook after registration. IAM validates and records that decision. IAM platform administrators with `applications.review` can also do this. The creator is only audit metadata, not a separate owner or source of authority. This is a narrow webhook approval: it does not approve the Application itself, change its status, or change its scopes. An Application requesting public access must complete Honeycomb publication review separately. Approval requires the current IAM application configuration revision, an idempotency key, and verified-channel step-up for `application.webhook.approve` bound to the internal Application UUID. The old destination stays active until approval; testing environments continue activating endpoints immediately.

IAM stores base_url as a complete backend origin, for example `https://backend.iam.teamofsilicons.com`. Anyone can discover a public application's base_url without authentication. A private application requires an authenticated caller with permission to access that application; otherwise IAM must not disclose the URL. This rule applies to users and application callers. Knowing a URL does not grant protected API or OBO access. 

The organisation administers the application. Public applications may be used across organisations; private applications may only be used by current members of their owning organisation, with grants limited to that organisation.

Private applications bypass provider approval for critical IAM scopes and critical OBO scopes. IAM records this as a private-app exemption, not a provider approval. Declared and effective scopes, scope eligibility, user consent and the represented user's resource permissions still apply. IAM must enforce the owning-organisation restriction during login, token exchange, refresh, introspection, API access and OBO exchange/verification, including after membership removal. A request to become public does not lift this restriction: all required critical-scope approvals and Honeycomb review must pass before IAM accepts public activation. The exemption cannot be reused as an approval for public access. 


### Client Secret Rotation

For rotating an application secret, the current org_owner or org_admin requests it through Honeycomb. IAM verifies the acting user and the required step-up, generates the replacement, stores its verification hash and returns the new secret through the protected response. The old secret stops authenticating new requests once the rotation is accepted. The same request can replay the same secret for 10 minutes; after that it cannot be retrieved again and a lost secret needs another explicit rotation. Rotation must not silently repeat when a response is lost. Secrets never appear in ordinary reads, notifications or CLI archives. 


# Communicating with Honeycomb

IAM accepts application configuration, bundle membership, scope decisions, secret rotations and testing instructions through a dedicated authenticated service integration. For user actions, verify the acting user's current organisation or provider-review authority and any required step-up as well. An actor_id or ordinary app login token is not enough. Scheduled testing operations require explicit service authority.

Each mutation needs an operation_id, idempotency key, environment context and expected IAM revision. Configuration revisions are separate from app release versions. Validate and save the accepted state and its notification atomically, reject conflicting revisions and return the effective state. Expose operation status and current records for reconciliation. Retrying completed work must not repeat it, including after the response replay window expires.

Send signed management notifications for scope decisions, revocations, webhook activation, credential versions, app availability and testing operation results. Include event_id, resource ID, environment and revision, with retries and replay support. Never include app secrets or user tokens. This subscription is separate from ordinary application webhooks, which still go directly to their authorized recipients.

IAM itself has an application identity. Initial setup must create or reuse IAM's and Honeycomb's authentication records and the separate integration identity without needing an already-running app catalog. Initial signup and login must work independently. Ordinary IAM app credentials do not grant unrestricted identity-service authority.

During migration preserve existing app and environment IDs, ownership, credentials, sessions, approvals and consents. Retire or compatibly forward the old management routes so they cannot remain independent writers. Login, token checks, discovery and OBO continue using IAM's accepted records without contacting Honeycomb on every request.

# How would login work for configured apps

For configured . pplications, it can trigger a login which would bring them to [`auth_base_url`/login?app_id="silicon-briefcase"&redirect_uri="localhost:3000"]

in iam if the user is already logged in, move on to the next step. Otherwise prompt the login.

Now app id must be mentioned for it to be considered as an external configured app login, otherwise it's an internal silicon iam login itself. And if redirect_uri is present add [?slt="{the short live token h. re}"] and if no redirect_uri is present instead of redirecting, show them another screen with their short live token mentioning "if requested, this is your short live token" and below that the token, this page would only be valid till the expiry time is hit, then display token expired, or if login successfully happens using the short live token display authenticated successfully. 

The short lived token would have a lifespan of 2 minutes. The short lived token would be used to request to iam by the application along with it's secret, if the request for the said app-id has the correct app-secret to it, if it's a valid request give the access and the refresh token, otherwise deny the request.

For each application login, during the login in IAM, the user can select which all organisations it wanna give the app access to after seeing the application validation screen. Unless the application's owning organisation has the configured trusted-organisation consent-screen bypass, show the consent screen with all the non critical and critical IAM and external app permissions this app demands. With that bypass, skip the consent screen and go directly to organisation selection. For a public app the user can select their permitted organisations; for a private app the only permitted organisation is the application's owning organisation and the user must be a current member. Then the app receives only its declared, user-approved scopes, within the user-selected organizations The app can always do an additive organisation where they can get access to more organisations on top of the already existing orgs. So they can get access to more organisations without needing to loose access to the already existing organisations, and in this as well the same flow would be followed. 

The subject token was issued **to the calling app**, remains valid, and represents the same user throughout the exchange.

The app cannot supply organisations to enlarge the login grant. IAM determines the choices: public apps let the user choose permitted organisations, while private apps are restricted to their owning organisation. 

For each login that takes place also store the login history, app specific and also user wide.


# Bundle Login

IAM receives the accepted bundle details and member apps from Honeycomb. Check that the organisation has bundle eligibility and all member apps belong to that organisation. During login show the bundle details and issue a separate short-lived token for each permitted member app. Each app exchanges its own token using its own secret. Apply the normal organisation, scope and consent rules to each member, including the configured trusted-organisation consent-screen exception.


# Trusted Orgs

There should be an concept of trusted org which is just a boolean flag which can just be configured from the database itself. By default trusted_org: false. 

If trusted org is true, then the organisation would be treated as an trusted organisation, they would have permission to create `Bundled applications` which are restricted to normal orgs. And for these trusted organisations, the consent screen during login where all the permissions requested are displayed that screen is not displayed. And just after loggin in they directly see the orgs screen where they select the orgs to give access to. 

It should be configurable if i just wanna give someone no consent screen or/and bundle applications. These are separate settings configured in IAM itself, so an organisation can have either one or both. Honeycomb uses the bundle eligibility returned by IAM when allowing bundle creation. 

The consent-screen exception is a separate IAM platform policy. When enabled, record the grant and policy used; consent checks accept that recorded grant. It does not bypass declared scopes, scope eligibility, required provider approvals, user permissions or private-app organisation restrictions. Ordinary app configuration cannot enable it.

`Docs Note`: In the docs don't mention anything about Trusted orgs, this is an internal concept. 


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

Tags are a way of grouping in the system and it also gives the carbon access to the silicons with the same tag. Tags is a list that can be defined and further updated via the org_admins or org_owner. Tags can also be deleted by the org_admins or org_owner. 

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

IAM keeps the accepted base_url, OBO endpoints, requested and effective external scopes and approval records. These support discovery, consent, proof generation and verification.

For all the apps, it should also be possible for inter app communications. Before allowing an OBO request to go forward, IAM must check that the calling application has the exact action it wants to perform in its effective app scope. This means the target app_id and endpoint_id must be declared in app_scope.external, accepted by IAM, included in the user's current consent for the selected organisation, and approved by the provider if critical and the calling app is public. If the calling app is private, IAM instead checks its accepted private status and current owning-organisation membership and grant; provider approval is not required, but the exact endpoint scope and OBO proof are still required. So say Honeycomb wants to upload a file to briefcase, it must have `tos>briefcase` and `files.upload` in scope; having another briefcase endpoint in scope is not enough. If that action is missing, waiting for an approval required for public access, revoked or not consented to, IAM must reject the exchange without issuing a proof. IAM must check this again when the receiving application verifies the proof, so an action removed from scope after issuance cannot still be performed with an older proof.

Application A sends an request to IAm to do OBO for Application B, along with the request it attaches an hash of (`HMAC-SHA256(app_secret,timestamp + "." + method + "." + path + "." + body_sha256 + "." + idempotency_key)`) and the request it wants to send to application b and the metadata (this is just the metadata and not the actual request, so say for files it doesen't actually send the file), if the request endpoint exists (checked against IAM's latest accepted configuration) and the metadata is also valid it returns a proof_token to Application A that is valid for one successful verification or the endpoint's configured TTL (whichever happens first), with a default TTL of 5 minutes (300 seconds) from issuance. Application A then requests Application B with the proof_token and the actual request (so if there's a file it would include the actual file here) while sending this request the details of the request would all be hashed. Application B would then request IAm to validate all the requests and once validated then only would it execute the task if the proof has not expired and has not already been consumed. IAM consumes the proof on successful verification.  

Each OBO endpoint can optionally define ttl_seconds. If omitted IAM uses 300 seconds; if provided it must be a positive integer in seconds. IAM only accepts this setting from an authorized configuration change by the provider application's current org_owner or org_admin. IAM stores the accepted setting and fixes each proof's expiry at issuance using that value. The calling application cannot choose a different TTL during exchange. A later TTL change applies to newly issued proofs and does not change the expiry of an existing proof. An idempotent retry returns the original proof and expiry without extending its lifetime. Revocation, consent and current endpoint authorization are still checked before expiry as well.

An authorized application can fetch another application's available OBO endpoints and metadata requirements from IAM's accepted records, including across organisations where permitted. The actual OBO request body goes directly between the applications.

Applications can request GET /api/v1/application-directory/{app_id} to receive app_id and the latest accepted base_url. Public lookups need no authentication. Private lookups require a user or application context authorized for that target; an arbitrary app_secret is not enough. Return an error when the app is unavailable or has no base_url. URL discovery grants no OBO access.

For accepted OBO definitions, require endpoint_id, path, metadata requirements where provided, a boolean critical flag and optional ttl_seconds. An app exposing endpoints must have a base_url. An existing endpoint_id cannot move to a different path. Configuration changes and provider decisions use the management integration described above.

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


For each exposed endpoint in OBO by an application it would either be Critical endpoint or Non Critical endpoint. This definition is compulsorry for each obo exposed endpoint.

The critical/non critical definition is used to let the users know that the other application is trying to access the application on their behalf and the actions they wanna do, the definition helps us let the users distinguish easily. 

For a critical endpoint requested by a public app, IAM validates and records the provider application's current org_owner or org_admin approval before enabling that scope. A private calling app bypasses provider approval while IAM enforces its owning-organisation restriction. User consent and the exact declared endpoint scope are required in both cases. Honeycomb publication approval does not replace provider approval for public apps. IAM must check current scopes, consent, application status and endpoint configuration both when issuing and verifying the proof. Once a removal or revocation is accepted, an earlier proof or consent must not bypass it. A change to critical requires provider approval for public callers; private callers remain subject to the private-app exemption and all other authorization checks. The receiving application still checks its own resource permissions before doing the task. These OBO rules apply equally to platform applications.

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


# Versioning

For versioning we have Contract Governance/API/service contract lifecycle management. We will have:

1) Contract versioning / API versioning
2) Protocol Negotiation
3) Backward compatibility
4) Consumer-driven contract testing
5) Deprecation and sunset management - if 0 requests for 7 days, sunset that version
6) Compatibility matrix
7) Version policy


# App Verification

IAM provides application verification for inter-app communication. An application requests an `app_access_key` by authenticating with its `app_id` and `app_secret`. IAM verifies the supplied secret against its stored verification hash, then generates a cryptographically random, short-lived `app_access_key`. Its lifetime defaults to 5 minutes; the application may request a lifetime from 1 to 60 minutes inclusive. Reject lifetimes outside this range.

Return the key and its expiry to the authenticated application. Store only the key's hash, together with the authenticated application's `app_id`, expiry, revocation state and environment context, including the current testing generation when applicable. Multiple keys may remain valid concurrently, each with its own expiry. Never include keys in logs or ordinary application reads.

The calling application presents its `app_id` and `app_access_key` to the receiving application. To verify them, the receiving application authenticates to IAM using its own application credentials and submits the calling application's `app_id` and `app_access_key`. IAM hashes the submitted key and compares it with the stored record. Verification requires a matching calling `app_id`, an unexpired and unrevoked key, an active calling application, and matching environment context. Test keys must also belong to the current testing generation and must never verify in production. Accepted app-secret rotation revokes keys issued under the previous secret; disabling an application revokes its outstanding keys.

Successful verification returns `{valid_key: true, valid_till, app_id}`, using the expiry and application ID from the stored record. An unknown, expired, revoked or mismatched key returns `{valid_key: false}` without application details. Invalid credentials for the receiving application return an authentication error.

A valid `app_access_key` proves the calling application's identity. The receiving application remains responsible for authorizing the requested action; this key does not grant user permissions or replace OBO.


# Testing Environments

IAM provides isolated identity and authentication inside testing environments managed by Honeycomb. IAM only prepares and manages its own test records; the environment lifecycle and other applications' test data are outside its ownership.

### Test Records

Each environment has an environment_id, owning organisation, revision, key version and cleaning generation. Test data stays in a separate database from production, with every record associated with its environment_id. Preparing an environment starts with no production users, sessions or business data.

For requested app imports, preserve the original app_id and owning organisation, copy the specified configuration revision and generate fresh test app_secrets. So google>drive remains google>drive inside the test organisation google. Test root authority can create test owners without changing production ownership. A test-only app cannot claim an existing production app_id. Configuration refreshes must be explicit; production changes do not silently change test records.

### Test Authentication

Use the same IAM APIs with X-Testing-Environment-Key selecting the environment. Validate the key against the current environment state and key version. The key gives root authority only inside that environment, including creation and management of test identities.

Access tokens, refresh tokens, short-lived tokens, STKs, app secrets, sessions and OBO proofs must resolve to the same environment and current cleaning generation. Invalid, disabled or mismatched context must fail without falling back to production. App-secret validation must return the authenticated environment context; simply receiving a secret is not proof of test access or a user's identity.

Login, consent, base URL discovery and OBO use that environment's accepted records. The normal scope and private/public access rules still apply. Test grants and approvals never grant production access. For email and phone verification use 000000, retaining challenge expiry, attempt limits and session checks, without sending real verification emails or SMS.

### Test Webhooks

Use test:{testing_key, metadata:{event_id, environment_id, generation, ...}, data:{...}} and sign the complete raw body. Keep resource revisions for ordering and reject delivery or replay from an earlier cleaning generation. Redact the root key from logs, traces and stored event payloads; insert it from protected credential storage when signing an authorized delivery.

An imported app's existing webhook signing key can remain internal to IAM, but must never be revealed to the tester. Replacing a test destination uses a supplied or newly generated test-only signing secret and activates immediately without changing production configuration.

### Lifecycle Instructions

Accept preparation, app import, key rotation, cleaning, disabling, restoration, purging and activation through the authenticated service integration. These operations must work independently of the test sessions being invalidated. Check revisions, record progress durably and acknowledge only IAM's own completion. Repeated operations must be safe, and failed or pending work must be readable for reconciliation.

For rotation, install the new key version and reject the old key, including cached copies. For cleaning, block access, advance the generation and erase IAM's test identities, app imports, grants, sessions, proofs and related data while keeping the environment identity and current key. Fresh imports receive fresh credentials.

For deletion, disable access and retain recoverable data until instructed to restore or purge. Restore only the matching retained state; it cannot undo a clean. Purging permanently removes test data and keys. Keep only minimal lifecycle audit without erased payloads or secrets. Resume access only after an accepted activation instruction for the prepared revision and generation.

Report IAM's test activity and operation results to Honeycomb. IAM does not independently schedule environment retirement or claim cleanup is complete in other applications.


---

**For any changes in any of the things mentioned above, maintain a version for all of the changes.** 

Default production retention: audit 7 years, login history 1 year, expired challenges 30 days, ordinary expired token metadata 90 days, compromised families 1 year, webhook attempts 45 days. Test payloads and credentials follow Honeycomb cleaning and purge instructions; production retention defaults must not preserve erased test data.

Be sure to always keep a good store of login history, the approvals they have given, etc. 

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

The rust package would be stateless whereas the cli would be statefull. CLI built on top of the rust package.

For how this CLI is built, rust as the programming language, but can use anything under the hood that is needed. Maybe rust, or node, or shell, as and when the work comes. That is decided by the implementor based on the work. If something requirs a UI (like graph, live, video, images etc). for that the UI has an endpoint that can be viewed/used/downloaded and the cli gives the link to that.

The primary Interface is the Rust Package. CLI is built using the Rust Package only and doesn't have any feature that the Rust package does not.

if you need a local store for auth or something else, use `{home_dir}/.{appname}/dir`.

The default home dir is `~`. If `SILICON_HOME` is present in the enviorment variables, use that as the home directory by default. 

For both package and the cli write detailed docs on how to use the package and how to use the cli, and also another doc on how to use the package. 

Package and CLI must only expose the client side actions, and not the internal actions performed by the backend. For the CLI follow the standard command line grammar rules, and also include a -h command that shows all the possible commands.

And there should be an command to configure the home directory where the information is stored:  `{home_dir}/.{appname}/dir`. This can be confitgure via `iam config home {location}`. If it's not a directory give an error not a directory. 

Ship IAM's CLI as a Honeycomb-compatible archive with the IAM app release. The Rust client library remains available through crates and follows the consuming project's dependency configuration; it must not update itself at runtime.

In the CLI and the and the client both there must be silicon login commands and endpoints, this command would ask the silicon for the sid and the stk, an optional argument can be passed for the app-id, if the app-id is passed generate a short lived token that can be used by that application for further authenticating the said silicon. 

When the carbon login is initiated the simple login can happen, even for the carbon it's possible to mention an app-id which would return the short lived token after the login happens. 

If the carbon/silicon is already logged in directly return the short lived token. 

For working inside an existing test environment, use iam --test <environment_id> <command>. The CLI resolves the authorized environment key from protected local configuration and sends the test header; the environment ID alone is not a credential. Missing or invalid test context returns an error without falling back to production. Test-only identity actions still require --test. Environment management belongs to Honeycomb.

The IAM client, CLI and frontend expose identity, organisation, login, consent, sessions and runtime OBO actions. Do not expose internal service-management operations as ordinary user commands.

It should expose `--help` command, so the user can run `iam --help` and get the entire help docs. 


# Cli experience

CLI is the primary way to interact with IAM Apps. It should be built for both Carbons & Silicons. Any other interface (like website) will be a subset of the CLI.

The cli should never ask for credentials from either silicon or carbon. it should just ask for short lived tokens that the user can generate from the official iam cli, or from the web where the the user is sent to auth concent screen.

CLIs get SILICON_HOME env variable where it should store all the details. Its home, so you should use that as base, and make their own hidden folders to keep their information.

Specific apps that could benefit from using ISI env variable should do that. eg: dm.

ISI are internal silicons. If silicon is a brain, then isi are parts of the brain. store this inside metadata, or main data if its super useful. ISI may or may not be present. make sure to not rely on it in such a way that things break. consider ISI as useful additional information.

every app cli must support the following commands:

`app iam --json` gives {app_id: "...", ...}

`app login "..."` takes in a short lived auth token generated by silicon interpretter.

`app login status --json` tells if its {authenticated: true, ...}


App Internals:
All apps are suggested to make a rust library which is stateless. then 2 things that uses the rust library: always running daemon, and a cli interface that talks to the daemon.

The docs should show how to install IAM using `honeycomb install <configured-iam-app-id>`, followed by IAM login instructions. Initial platform deployment and Honeycomb bootstrap must also have a documented direct setup path because the first deployment cannot depend on an already-running Honeycomb catalog.

CLI design should be focused on giving details and helping finding the right command to use. CLI will often have lots of commands and it should be like a tree that can be traversed using --help.

CLI documentation should be bundled inside the cli itself. On each print of the cli documentation using --help or otherwise, it should show what this command is for, how its often used (perhaps in conjunction with other commands if applicable) and then a list of flags etc it takes in.

Follow the CLI grammar. These CLIs can be used by humans, but more often than not, it'll be used by an agent who prefers to know why something broke and so it can figure out ways to fix it. Don't just say something went wrong... tell it exactly what and why.

A good rule of thumb is: these CLIs are being made for someone who understands ins-and-outs of technology. Make like a programming language that gives very specific and helpful errors and outputs compared to a web interface where all errors are hidden until absolutely critical.

All CLIs must have a report bug feature that also optionally takes in a PR ref if the agent did not just find a bug but also patched it. 

iam report `<report-message>` --pr `<pr-link>` and if someone just reports the bug, without the pr, show them a message, you can also put a pr in the repo (`repo-link`). 

Everytime a bug is reported use postmark to mail [saketdev12@gmail.com, shubhastro2@gmails.com, bugs@teamofsilicons.com]

Since all TOS applications are open sourced, any bug can be discovered, replicated, patched and a pr can be raised. Allow all such edge cases be figured out by the agent instead of fixing it ourselves based on a bug report.

Only a bug report submitting is possible, but its encouraged to give a lot more details and also attach a PR if possible.

Give the information of the github repo, online docs, rust package, etc inside the cli itself.

The CLI as i told before is a tree of documentation. Show possible paths, and then let someone go deeper along with documentation.


# Docs

There are two kinds of documentations: informative & instructive.

Always keep instructive documentation up front, easy to use, direct with clear instructions & link to informative documents to know why its done this way. Instructive documents should be the landing point of the product for both carbons & silicons.

It can give carbon the instructions on how to install & use it, or how to ask their silicon to use it.

For silicons, it can be that, but also how to do a lot more with it. Esp. things like building on top of it. Make it very clear what is expected, what is mandatory and how does the system work.

Then the silicon can dig deeper into the informative documentation to know all the possible ways to do it, & why its done the way its done.

While both carbons and silicons can read the documentation, it'll likely be more silicon. So design it for silicons. The more reasons you give, the better a silicon would be at making a judgement call of how to do something.

Since all IAM apps can both be used as is, and also built on top of... its imp to write documentation for both. Usage docs & Development docs.

# Telemetry

All IAM apps use Space Station [https://spacestation.teamofsilicons.com/docs] for telemetry. Telemetry is opted-in by default but can be opted out from settings if the user wants.

Space Station is also a rust package which can be used from within the backend, or daemon, or cli to send telemetry.

Record as many things as you think might be useful to diagnose or follow traces later.

Since space station is just an event store, make sure to include all the source, step, progress, etc information inside each event. some of the system information is automatically added to the metadata so you need not add that.

push context-rich, self-contained events.

Space Station also support web, for web it has 2 possible pathways: analytics & events. Most of the Analytics is self captured and you can define a seperate event store from the web.


# Configurability

We ship highly configurable apps with sensible defaults. Very much like VS Code. flags to toggle / customize behaviors.


# Updates

Honeycomb manages updates for its installed IAM CLI through `honeycomb update <configured-iam-app-id>` and any automatic update policy configured in Honeycomb. IAM must not run a second independent updater that can conflict with it. The IAM app release supplies the combined CLI archive; updating the CLI does not itself deploy or migrate the IAM backend.
