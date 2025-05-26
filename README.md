# ConditionalAccess
CA Policies that conform to the MS naming convention found https://learn.microsoft.com/en-us/azure/architecture/guide/security/conditional-access-framework

These were created to assist in standardizing Conditional Access policies in the same way that GPMC templates have for Active Directory

In https://portal.azure.com/#view/Microsoft_AAD_ConditionalAccess/ConditionalAccessBlade/~/Policies you have an **"Upload policy file"** option. There you can use these JSON.

Policies are split into 5 sections:

[Essentials](#essentials)\
[Privileged Access](#privileged-access)\
[Application Policies](#application-policies)\
[Non-human identities](#non-human-identities)\
[Risk-based](#risk-based)

When importing, use the **"Review + create"** option. This will allow you to set the User/Group inclusions and exclusions.
I would recommend setting these to **"Report-only"** until you are certain you have them set correctly.

At least one **Global Administrator** should be initially exempt from all policies created. This is typically your BreakGlass account/group. Only remove this exclusion once you have proven that another **Conditional Access Administrator** or **Global Administrator** has access to reverse any potential lockouts.

Default Settings are **in bold**. Settings you need to customize are **<ins>underlined in bold</ins>**.

## Essentials

### CA000-Global-BaselineProtection-AllApps-AnyPlatform-Block-Block legacy authentication v1.0
Users:  
    Include: **All Users**
    Exclude: None
Target resources:
    Resources (formerly cloud apps):
        Include: **All resources**
        Exclude: None
Network: No
Conditions:
    Device Platforms:
    Locations:
    Client apps: **Exchange ActiveSync clients** and **Other clients**
    Filter for devices:
    Authentication flows:
Grant: **Block access**
Session:

It is meant to be run without the Breakglass exception.

### CA001-Global-BaselineProtection-AllApps-AnyPlatform-MFA-Require MFA for all users v1.0
Users:
    Include: **All Users**
    Exclude: **<ins>Breakglass</ins>**
Target resources:
    Resources (formerly cloud apps):
        Include: **All resources**
        Exclude: **Microsoft Intune**, **Microsoft Intune Enrollment**
Network: No
Conditions:
    Device Platforms:
    Locations:
    Client apps:
    Filter for devices:
    Authentication flows:
Grant: **Grant access**, **Require authentication strength, Multifactor authentication strength**
Session:

### CA002-Global-AttackSurfaceReduction-AllApps-AnyPlatform-Block-Block non-business countries v1.0

Users:
    Include: **All Users**
    Exclude: **<ins>Breakglass</ins>**
Target resources:
    Resources (formerly cloud apps):
        Include: **All resources**
        Exclude:
Network: Yes
    Include: **<ins>Blocked access countries</ins>**
    Exclude: **<ins>Approved access countries</ins>**
Conditions:
    Device Platforms:
    Locations:
    Client apps:
    Filter for devices:
    Authentication flows:
Grant: **Block access**
Session:

The Approved access countries and Blocked access countries lists need to be created in Microsoft Entra Named Locations before making this policy

### CA003-Global-DataProtection-AllApps-AnyPlatform-SessionControl-8H session lifetime for managed devices v1.0

Users:
    Include: **All Users**
    Exclude: None
Target resources:
    Resources (formerly cloud apps):
        Include: **All resources**
        Exclude: None
Network: No
Conditions:
    Device Platforms:
    Locations:
    Client apps: 
    Filter for devices: Yes
        Include: **device.trustType -eq "AzureAD" -or device.trustType -eq "ServerAD" -or device.trustType -eq "Workplace"**
    Authentication flows:
Grant: **Grant access**, **Sign-in frequency Periodic reauthentication 8 hours**
Session:

It is meant to be run without the Breakglass exception.

### CA004-Global-DataProtection-AllApps-AnyPlatform-SessionControl-3H session lifetime for unmanaged devices v1.0

Users:
    Include: **All Users**
    Exclude: None
Target resources:
    Resources (formerly cloud apps):
        Include: **All resources**
        Exclude: None
Network: No
Conditions:
    Device Platforms:
    Locations:
    Client apps: 
    Filter for devices: Yes
        Include:
        Exclude: **device.trustType -eq "AzureAD" -or device.trustType -eq "ServerAD" -or device.trustType -eq "Workplace"**
    Authentication flows:
Grant: **Grant access**, **Sign-in frequency Periodic reauthentication 3 hours**
Session:

It is meant to be run without the Breakglass exception.

### CA005-Global-BaselineProtection-CombinedRegistration-AnyPlatform-MFA-Require MFA for registering security info v1.0

Users:
    Include: **All Users**
    Exclude: **<ins>Guest or external users</ins>**
Target resources:
    User actions: **Register security information**
Network: No
Conditions:
    Device Platforms:
    Locations:
    Client apps:
    Filter for devices:
    Authentication flows:
Grant: **Grant access**, **Require authentication strength, Multifactor authentication**
Session:

It is meant to be run without the Breakglass exception.

### CA006-Global-DeviceProtection-AllApps-WindowsPhone-Block-Block Unknown platforms v1.0

Users:
    Include: **All Users**
    Exclude: **<ins>Breakglass</ins>**
Target resources:
    Resources (formerly cloud apps):
        Include: **All resources**
        Exclude: None
Network: No
Conditions:
    Device Platforms: Yes
        Include: **Windows Phone**
        Exclude: **Android, iOS, Windows, macOS, Linux**
    Locations:
    Client apps:
    Filter for devices:
    Authentication flows:
Grant: **Block access**
Session:

### CA007-Global-Data&AppProtection-AllApps-iOS&Android-APP-Require App Protection Policy v1.0

Users:
    Include: **All Users**
    Exclude: **<ins>Breakglass</ins>**
Target resources:
    Resources (formerly cloud apps):
        Include: **All resources**
        Exclude: **Microsoft Intune**, **Microsoft Intune Enrollment**
Network: No
Conditions:
    Device Platforms: Yes
        Include: **Android, iOS**
        Exclude: **WindowsPhone, Windows, macOS, Linux**
    Locations:
    Client apps:
    Filter for devices:
    Authentication flows:
Grant: **Grant access**, **Require app protection policy**
Session:

Policies in Report-only mode requiring compliant devices may prompt users on macOS, iOS, Android, and Linux to select a device certificate.

### CA008-Global-DataProtection-AllApps-iOS&Android-Compliance-Require Compliance policy v1.0

Users:
    Include: **All Users**
    Exclude: **<ins>Breakglass</ins>**
Target resources:
    Resources (formerly cloud apps):
        Include: **All resources**
        Exclude: **Microsoft Intune**, **Microsoft Intune Enrollment**
Network: No
Conditions:
    Device Platforms: Yes
        Include: **Android, iOS**
        Exclude: **WindowsPhone, Windows, macOS, Linux**
    Locations:
    Client apps:
    Filter for devices:
    Authentication flows:
Grant: **Grant access**, **Require device to be marked as compliant**
Session:

### CA100-Admins-IdentityProtection-AllApps-AnyPlatform-AuthStr-Require Phishing-Resistant MFA for Admin roles v1.0

Users:
    Include: **<ins>Select users and groups, Directory Roles</ins>**
    Exclude: **<ins>Breakglass</ins>**
Target resources:
    Resources (formerly cloud apps):
        Include: **All resources**
        Exclude:
Network: No
Conditions:
    Device Platforms:
    Locations:
    Client apps:
    Filter for devices:
    Authentication flows:
Grant: **Grant access**, **Require authentication strength, Phishing-resistant MFA**
Session:

You will need to select the Directory Roles. I recommend everything Administrator, Editor, Technician, Engineer, Specialist, Creator, Security, Developer, Attribute, Writer, Inviter, Analyst, Author since all of these have some kind of write-access to the environment, or access privileged information

### CA400-Guests-BaselineProtection-AllApps-AnyPlatform-MFA-Require MFA for all guest users v1.0

Users:
    Include: **Select users and groups, Guest or external users**
    Exclude: **<ins>Breakglass</ins>**
Target resources:
    Resources (formerly cloud apps):
        Include: **All resources**
        Exclude:
Network: No
Conditions:
    Device Platforms:
    Locations:
    Client apps:
    Filter for devices:
    Authentication flows:
Grant: **Grant access**, **Require authentication strength, Multifactor authentication**
Session:

Select all guest and external users

### CA401-Guests-ComplianceProtection-CombinedRegistration-AnyPlatform-TOU-Require TOU for security info for Guests v1.0

Users:
    Include: **Select users and groups, Guest or external users**
    Exclude: **<ins>Breakglass</ins>**
Target resources:
    User actions: **Register security information** 
Network: No
Conditions:
    Device Platforms:
    Locations:
    Client apps:
    Filter for devices:
    Authentication flows:
Grant: **Grant access**, **<ins>TOU</ins>**
Session:

Select all guest and external users

You must create the Terms Of Use before configuring this policy. You can create a bare bones TOU, install the policy and then flesh out the TOU later if needed

### CA900-Breakglass-IdentityProtection-AllApps-AnyPlatform-AuthStr-Require Phishing-resistant Authentication for BreakGlass Accounts v1.0

Users:
    Include: **<ins>Breakglass</ins>**
    Exclude: None
Target resources:
    Resources (formerly cloud apps):
        Include: **All resources**
        Exclude:
Network: No
Conditions:
    Device Platforms:
    Locations:
    Client apps:
    Filter for devices:
    Authentication flows:
Grant: **Grant access**, **Require authentication strength, Phishing-resistant MFA**
Session:

Critical policy, as the Breakglass account/group is exempt from most of the other policies. It is a strong recommendation that Breakglass accounts are an onmicrosoft.com account with no licenses and Global Administrator role. A FIDO2 physical key with a PIN is the recommended authentication method, and ideally you will provision three Breakglass accounts, with one kept onsite in a safe with the login details, two kept offsite at different locations.

## Privileged Access

### CA101-Admins-AttackSurfaceReduction-AllApps-iOS&Android-Block-Block iOS & Android access v1.0
This is set to **<ins>Select users and groups, Directory Roles</ins>** with **<ins>Breakglass</ins>** exclusion, Target resources **All resources**, Conditions Device platforms Include **Android, iOS** Exclude  **WindowsPhone, Windows, macOS, Linux**, Grant **Block access**

You will need to select the Directory Roles. I recommend everything Administrator, Editor, Technician, Engineer, Specialist, Creator, Security, Developer, Attribute, Writer, Inviter, Analyst, Author since all of these have some kind of write-access to the environment, or access privileged information

### CA102-Admins-IdentityProtection-AllApps-AnyPlatform-MFA-Require MFA for Medium & High risk Sign-in v1.0
This is set to **<ins>Select users and groups, Directory Roles</ins>** with **<ins>Breakglass</ins>** exclusion, Target resources **All resources**, Conditions Sign-in risk **High, Medium**, Grant **Require authentication strength, Passwordless MFA**

CA022 applies similar controls to all users. CA107 extends these controls with Password reset. CA025 blocks High sign-in risk.

### CA103-Admins-DataProtection-AllApps-AnyPlatform-SessionControl-Non-persistent browser session & 4h frequency v1.0
This is set to **<ins>Select users and groups, Directory Roles</ins>** with **<ins>Breakglass</ins>** exclusion, Target resources **All resources**, Session **Sign-in frequency Periodic reauthentication, 4 hours, Persistent browser session, Never persistent**

You will need to select the Directory Roles. I recommend everything Administrator, Editor, Technician, Engineer, Specialist, Creator, Security, Developer, Attribute, Writer, Inviter, Analyst, Author since all of these have some kind of write-access to the environment, or access privileged information

### CA104-Admins-DataProtection-AdminPortals-Windows&MacOS-Compliance&AuthStr-Require Compliant device & Phishing-resistant Auth for Admin Portals v1.0
This is set to **<ins>Select users and groups, Directory Roles</ins>** with **<ins>Breakglass</ins>** exclusion, Target resources **Microsoft Admin Portals**, Conditions Device platforms Include **Windows, macOS** Exclude  **Android, iOS, WindowsPhone, Linux**, Grant **Require authentication strength, Phishing-resistant MFA, Require device to be marked as compliant** **Require all the selected controls**

You will need to select the Directory Roles. I recommend everything Administrator, Editor, Technician, Engineer, Specialist, Creator, Security, Developer, Attribute, Writer, Inviter, Analyst, Author since all of these have some kind of write-access to the environment, or access privileged information

Policies in Report-only mode requiring compliant devices may prompt users on macOS, iOS, Android, and Linux to select a device certificate.

### CA105-Admins-IdentityProtection-PIM-AnyPlatform-MFA-Require MFA for PIM elevation v1.0
This is set to **<ins>Select users and groups, Directory Roles</ins>** with **<ins>Breakglass</ins>** exclusion, Target resources **Authentication context, c1**, Grant **Require authentication strength, Phishing-resistant MFA**, Session **Sign-in frequency, Every time**

You will need to select the Directory Roles. I recommend everything Administrator, Editor, Technician, Engineer, Specialist, Creator, Security, Developer, Attribute, Writer, Inviter, Analyst, Author since all of these have some kind of write-access to the environment, or access privileged information

Only available for creation if PIM is enabled, and you have created an Authentication Context.

### CA106-Admins-AttackSurfaceReduction-O365-AnyPlatform-Block-Block access to Office 365 v1.
This is set to **<ins>Select users and groups, Directory Roles</ins>** with **<ins>Breakglass</ins>** exclusion, Target resources **Office 365**, Grant **Block access**

You will need to select the Directory Roles. I recommend everything Administrator, Editor, Technician, Engineer, Specialist, Creator, Security, Developer, Attribute, Writer, Inviter, Analyst, Author since all of these have some kind of write-access to the environment, or access privileged information

### CA107-Admins-IdentityProtection-AllApps-AnyPlatform-MFA&PWDreset-Require MFA & Password reset for Medium & High user-risk v1.0
This is set to **<ins>Select users and groups, Directory Roles</ins>** with **<ins>Breakglass</ins>** exclusion, Target resources **All resources**, Conditions User risk **High, Medium**, Grant **Require authentication strength, Passwordless MFA, Require password change** **Require all the selected controls**

You will need to select the Directory Roles. I recommend everything Administrator, Editor, Technician, Engineer, Specialist, Creator, Security, Developer, Attribute, Writer, Inviter, Analyst, Author since all of these have some kind of write-access to the environment, or access privileged information

CA022 applies similar controls to all users. CA102 mirrors these controls without Password reset. CA025 blocks High sign-in risk.

### CA500-GuestAdmins-AttackSurfaceReduction-O365-AnyPlatform-Block-Block access to Office 365 v1.0
This is set to **<ins>Select users and groups, GuestAdmins group</ins>** with **<ins>Breakglass</ins>** exclusion, Target resources **O365**, Grant **Block access**

GuestAdmins is a defined group, these policies are only for when you want to apply different rules to external Admins than internal Admins with the same role. To do this you need to edit CA100-CA107 and specify defined Admin groups rather than use Roles.

### CA501-GuestAdmins-IdentityProtection-PIMelevation-AnyPlatform-MFA-Require MFA for PIM elevation v1.0
This is set to **<ins>Select users and groups, GuestAdmins group</ins>** with **<ins>Breakglass</ins>** exclusion, Target resources **PIM**, Grant **Require authentication strength, Multifactor authentication**

GuestAdmins is a defined group, these policies are only for when you want to apply different rules to external Admins than internal Admins with the same role. To do this you need to edit CA100-CA107 and specify defined Admin groups rather than use Roles.

Only available for creation if PIM is enabled, and you have created an Authentication Context.

### CA502-GuestAdmins-IdentityProtection-AllApps-AnyPlatform-MFA&PWDreset-Require MFA & Password Reset for Medium & High user-risk Guest admins v1.0
This is set to **<ins>Select users and groups, GuestAdmins group</ins>** with **<ins>Breakglass</ins>** exclusion, Target resources **All resources**,Conditions User risk **High, Medium**, Grant **Require authentication strength, Multifactor authentication, Require password change**

GuestAdmins is a defined group, these policies are only for when you want to apply different rules to external Admins than internal Admins with the same role. To do this you need to edit CA100-CA107 and specify defined Admin groups rather than use Roles.

### CA503-GuestAdmins-IdentityProtection-AllApps-AnyPlatform-MFA-Require MFA for Low+ sign-in risk for guest admins v1.0
This is set to **<ins>Select users and groups, GuestAdmins group</ins>** with **<ins>Breakglass</ins>** exclusion, Target resources **All resources**, Conditions Sign-in risk **High, Medium, Low**, Grant **Require authentication strength, Multifactor authentication**

GuestAdmins is a defined group, these policies are only for when you want to apply different rules to external Admins than internal Admins with the same role. To do this you need to edit CA100-CA107 and specify defined Admin groups rather than use Roles.

### CA504-GuestAdmins-ComplianceProtection-CombinedRegistration-AnyPlatform-TOU-Require TOU for security info for Guest Admins v1.0
This is set to **<ins>Select users and groups, GuestAdmins group</ins>** with **<ins>Breakglass</ins>** exclusion, Target resources **Security registration**, Grant **<ins>TOU</ins>**

GuestAdmins is a defined group, these policies are only for when you want to apply different rules to external Admins than internal Admins with the same role. To do this you need to edit CA100-CA107 and specify defined Admin groups rather than use Roles.

You must create the Terms Of Use before configuring this policy. You can create a bare bones TOU, install the policy and then flesh out the TOU later if needed

### CA505-GuestAdmins-DataProtection-AllApps-AnyPlatform-SessionControl-Non-persistent browser session & 1h frequency v1.0
This is set to **<ins>Select users and groups, GuestAdmins group</ins>** with **<ins>Breakglass</ins>** exclusion, Target resources **All resources**, Session **Sign-in frequency Periodic reauthentication, 1 hours, Persistent browser session, Never persistent**

GuestAdmins is a defined group, these policies are only for when you want to apply different rules to external Admins than internal Admins with the same role. To do this you need to edit CA100-CA107 and specify defined Admin groups rather than use Roles.

## Application Policies

### CA009-Global-IdentityProtection-AllApps-AnyPlatform-CompliantNetwork-Require Global Secure Access client active v1.0
This is set to **All Users** with **<ins>Breakglass</ins>** exclusion **Guest or external users, All external Azure AD organizations** exclusion **<ins>ServiceAccounts</ins>** exclusion **<ins>Admins</ins>** exclusion, Target resources **All resources** with **Microsoft Intune, Microsoft Intune Enrollment** exclusion, Locations **All** with **All Compliant Network locations** exclusion, Grant **Block access**

This requires that the Global Secure Access client is active. Breakglass, ServiceAccounts and Admins will need to be added to the exclusion.

### CA010-Global-AttackSurfaceReduction-Exchange&Sharepoint-Windows-TokenProtection-Enforce Token Protection for Exchange & Sharepoint on Desktop applications v1.0
This is set to **All Users** with **<ins>Breakglass</ins>** exclusion **Guest or external users, All external Azure AD organizations** exclusion **<ins>ServiceAccounts</ins>** exclusion **<ins>Admins</ins>** exclusion, Device platforms **Windows**, Client apps **Mobile app and desktop clients**, Target resources **Exchange, SharePoint**, Session **Token protection for session**

Token Protection binds a token to a device, preventing token relay attacks. Currently only supported for Exchange and SharePoint.

### CA011-Global-Data&AppProtection-O365-Windows-APP-Require App Protection Policy for Office 365 on the Web for Unmanaged Windows devices v1.0
This is set to **All Users** with **<ins>Breakglass</ins>** exclusion **Guest or external users, All external Azure AD organizations** exclusion **<ins>ServiceAccounts</ins>** exclusion **<ins>Admins</ins>** exclusion, Device platforms **Windows**, Client apps **Browser**, Target resources **O365**, Grant **App protection policy**

Requires a Windows App Protection Policy or a Compliant device when accessing O365.

### CA012-Global-Data&AppProtection-O365-AnyPlatform-AppRestriction-Enforce App Enforced Restrictions for Office 365 v1.0
This is set to **All Users** with **<ins>Breakglass</ins>** exclusion **<ins>ServiceAccounts</ins>** exclusion, Client apps **Browser**, Target resources **Exchange**, Session **App enforced restrictions**

Enforcing App Enforced Restrictions for Office 365 ensures the Session Timeout configured in the Microsoft 365 Admin portal is applied. This policy supersedes the session timeout settings in SharePoint.


### CA013-Global-Data&AppProtection-Exchange&Sharepoint-AnyPlatform-AppControl-Enforce Defender for Cloud Apps Session policy - Block Downloads for unmanaged devices v1.0
This is set to **All Users** with **<ins>Breakglass</ins>** exclusion **<ins>ServiceAccounts</ins>** exclusion, Conditions Filter for devices Exclude filtered devices **device.isCompliant -eq True**, Target resources **Exchange, SharePoint**, Session **Conditional Access App Control, Block downloads**

This policy uses the built-in *Block Downloads* App Control policy, preventing unmanaged devices from downloading company data to protect against data exfiltration. An alternate filter may be device.deviceOwnership -eq "Company" but this will be less stringent. The configured filter catches owned devices that have fallen out of compliance

### CA014-Global-Data&AppProtection-VariousApps-AnyPlatform-AppControl-Enforce Defender for Cloud Apps Session policy - Custom policy v1.0
This is set to **All Users** with **<ins>Breakglass</ins>** exclusion **<ins>ServiceAccounts</ins>** exclusion, Target resources **<ins>Custom</ins>**, Session **Conditional Access App Control, Use custom policy**

This policy enforces a custom policy configured in Defender for Cloud Apps, requiring setup of the app connector, app onboarding, Conditional Access App control, and the session policy to meet your enforcement requirements. License requirements apply.

### CA015-Global-DataProtection-Sharepoint-AnyPlatform-ComplianceOREntraJoined-Require managed device for Sharepoint access v1.0
This is set to **All Users** with **<ins>Breakglass</ins>** exclusion **<ins>ServiceAccounts</ins>** exclusion, Client apps **Mobile app and desktop clients**, Target resources **SharePoint**, Grant **Compliant device, Hybrid Azure AD joined device** **Require one of the selected controls**

Requiring a compliant device for SharePoint access protects company data against both intentional and accidental exfiltration, ensuring only managed devices can access SharePoint on mobile and desktop. Changing the *Require one of the selected controls* to *Require all the selected controls* would ensure that only Entra-joined Compliant devices can access SharePoint

### CA016-Global-DataProtection-Sharepoint-AnyPlatform-AppControl-Enforce limited web access for Sharepoint for unmanaged device v1.0
This is set to **All Users** with **<ins>Breakglass</ins>** exclusion **<ins>ServiceAccounts</ins>** exclusion, Client apps **Browser**, Target resources **SharePoint**,  Session **App enforced restrictions**

When used with CA015, further controls access to SharePoint through the policies in the SharePoint admin center

### CA017-Global-IdentityProtection-AllApps-AnyPlatform-SessionControl-Enforce never persistent browser session v1.0
This is set to **All Users**, Target resources **All resources**, Session **Persistent browser session, Never persistent**

This policy prevents users from saving their PTR tokens, requiring them to authenticate for each session. Depending on PTR lifetime, this enforces MFA or a phishing-resistant authentication method, such as a security key or Windows Hello for Business, aligning with the Zero Trust principle of Verify Explicitly.

It is meant to be run without the Breakglass exception.

### CA901-Marketing-IdentityProtection-GSA-AnyPlatform-SecurityProfile-Enforce Entra Internet Access Security profile for Marketing v1.0
This is set to **<ins>Marketing</ins>** with **<ins>Breakglass</ins>** exclusion, Target resources **<ins>Custom</ins>**, Session **<ins>Custom</ins>**

You will need to define the Marketing group, the Target resources and the Session resources. They are Network Access Security policies and Global Secure Access profiles

## Non-human identities

### CA800-ServiceAccounts-DataProtection-AllApps-AnyPlatform-Compliance-Require compliant device for untrusted networks for Service Accounts v1.0
This is set to **<ins>Service Accounts</ins>** with **<ins>Breakglass</ins>** exclusion, Locations Include **All** Exclude **All Trusted**, Target resources **All**, Grant **Grant access, Compliant device**

This policy requires Compliant devices for Service Accounts when on an untrusted network. For added security, removing the Exclude All Trusted would ensure that every device a Service Account is using has to be a Compliant device, however that adds to the complexity required in device compliancy.

### CA801-ServiceAccounts-AttackSurfaceReduction-AllApps-AnyPlatform-Block-Block untrusted locations v1.0
This is set to **<ins>Service Accounts</ins>** with **<ins>Breakglass</ins>** exclusion, Locations Include **All** Exclude **All Trusted**, Target resources **All**, Grant **Block access**

This policy prevents Service Accounts from accessing resources from untrusted locations.

### CA802-ServiceAccounts-DataProtection-AllApps-AnyPlatform-Block-Enforce CAE strict location v1.0
This is set to **<ins>Service Accounts</ins>** with **<ins>Breakglass</ins>** exclusion, Locations Include **All** Exclude **All Trusted**, Target resources **All**, Grant **Block access**, Session **Continuous access evaluation, Strictly enforce location policies**

Protects against location-based attacks by ensuring Service Accounts are only accessible from trusted locations, enforcing continuous access evaluations for real-time security.

### CA803-ServiceAccounts-IdentityProtection-AllApps-AnyPlatform-Block-Block Medium & High user risk v1.0
This is set to **<ins>Service Accounts</ins>** with **<ins>Breakglass</ins>** exclusion, User risk **High, Medium**, Target resources **All**, Grant **Block access**

This policy blocks Risky user behavior from Service Accounts.

### CA804-ServiceAccounts-IdentityProtection-AllApps-AnyPlatform-Block-Block Medium & High sign-in risk v1.0
This is set to **<ins>Service Accounts</ins>** with **<ins>Breakglass</ins>** exclusion, Sign-in Risk **High, Medium**, Target resources **All**, Grant **Block access**

This policy blocks Risky sign-in behavior from Service Accounts.

### CA805-ServiceAccounts-AttackSurfaceReduction-AllAppsExcludedMSFT-AnyPlatform-Block-Block unneeded applications v1.0
This is set to **<ins>Service Accounts</ins>** with **<ins>Breakglass</ins>** exclusion, Target resources **All** with **Microsoft Admin Portals** exclustion **Windows Azure Service Management API** exclusion, Grant **Block access**

This policy blocks access to all areas that a Service Account has no need to touch. It can be reconfigured depending on need.

### CA902-WorkloadIDs-AttackSurfaceReduction-AllApps-AnyPlatform-Block-Block untrusted locations v1.0
This is set to **<ins>Workload IDs</ins>** with **<ins>Breakglass</ins>** exclusion, Locations Include **All** Exclude **All Trusted**, Target resources **All**, Grant **Block access**

This policy prevents Workload IDs from accessing resources from untrusted locations.

### CA903-WorkloadIDs-IdentityProtection-AllApps-AnyPlatform-Block-Block Medium & High user risk v1.0
This is set to **<ins>Workload IDs</ins>** with **<ins>Breakglass</ins>** exclusion, Service Principal Risk **High, Medium**, Grant **Block access**

Protects against compromised workload identities by blocking access for accounts that show signs of risky behavior, reducing potential breaches. Risk is calcuated using Microsofts algorithm, which you should be familiar with before enabling this policy.

### CA904-WorkloadIDs-DataProtection-AllApps-AnyPlatform-Block-Enforce CAE strict location v1.0
This is set to **<ins>Workload IDs</ins>** with **<ins>Breakglass</ins>** exclusion, Locations Include **All** Exclude **All Trusted**, Target resources **All**, Grant **Block access**, Session **Continuous access evaluation, Strictly enforce location policies**

Protects against location-based attacks by ensuring workload identities are only accessible from trusted locations, enforcing continuous access evaluations for real-time security.

## Risk-based

### CA018-Global-DataProtection-AllApps-AnyPlatform-Block-Block Elevated insider risk v1.0
This is set to **All Users** with **<ins>Breakglass</ins>** exclusion **<ins>ServiceAccounts</ins>** exclusion, Target resources **All resources**, Conditions Insider Risk level **Elevated**, Grant **Block access**

Blocks all accounts from behavior deemed an Elevated Insider risk. Breakglass and any Service accounts should be exempted as they are not supported for this risk type.

Requires M365 E5 Compliance add-on license.

### CA019-Global-DataProtection-O365-AnyPlatform-Block-Block business critical apps for Moderate insider risk v1.0
This is set to **All Users** with **<ins>Breakglass</ins>** exclusion **<ins>ServiceAccounts</ins>** exclusion, Target resources **O365**, Conditions Insider Risk level **Moderate**, Grant **Block access**

Blocks all accounts from behavior deemed a Moderate Insider risk within O365. Breakglass and any Service accounts should be exempted as they are not supported for this risk type.

Requires M365 E5 Compliance add-on license.

### CA020-Global-AttackSurfaceReduction-AllApps-AnyPlatform-Block-Block Device code flow v1.0
This is set to **All Users** with **<ins>Breakglass</ins>** exclusion, Target resources **All resources**, Conditions Authentication Flows **Device Code Flow**, Grant **Block access**

Device code flow authentication, which allows authentication from a different device, is disabled via this policy, this is due to this authentication type being vulnerable to different attacks such as impersonation, especially in phishing.

This policy will require testing for legitimate uses, specifically devices with limited interaction.

### CA021-Global-IdentityProtection-AllApps-AnyPlatform-MFA&PWDreset-Require Password reset and MFA for High user risk v1.0
This is set to **All Users** with **<ins>Breakglass</ins>** exclusion **Guest or external users, All external Azure AD organizations** exclusion **<ins>ServiceAccounts</ins>** exclusion **<ins>Admins</ins>** exclusion, Target resources **All resources**, Grant **Require authentication strength, Multifactor authentication, Require password change** **Require all the selected controls**, Session **Sign-in frequency, Every time**

### CA022-Global-IdentityProtection-AllApps-AnyPlatform-MFA-Require MFA for Medium & High sign-in risk v1.0
This is set to **All Users** with **<ins>Breakglass</ins>** exclusion **<ins>ServiceAccounts</ins>** exclusion **<ins>Admins</ins>** exclusion, Target resources **All resources**, Conditions Sign-in Risk **High, Medium**, Grant **Require authentication strength, Multifactor authentication**, Session **Sign-in frequency, Every time**

CA102 applies similar controls to admins. CA107 extends these controls with Password reset. CA025 blocks High sign-in risk.

### CA023-Global-IdentityProtection-AllApps-AnyPlatform-MFA-Require MFA for Low & Medium user risk v1.0
This is set to **All Users** with **<ins>Breakglass</ins>** exclusion **Guest or external users, All external Azure AD organizations** exclusion **<ins>ServiceAccounts</ins>** exclusion **<ins>Admins</ins>** exclusion, Target resources **All resources**, Conditions User Risk **Medium, Low**, Grant **Require authentication strength, Multifactor authentication**

Enforcing MFA on users with low and medium risk, allows self-remediation for lower-confidence flagging, without inconveniencing the user too much. Even at lower levels, MFA serves as a critical stopgap to prevent unauthorized access.

### CA024-Global-ComplianceProtection-AllApps-AnyPlatform-TOU-Require TOU acceptance for Minor insider risk v1.0
This is set to **All Users** with **<ins>Breakglass</ins>** exclusion **<ins>ServiceAccounts</ins>** exclusion **<ins>Admins</ins>** exclusion, Target resources **All resources**, Conditions Insider Risk level **Minor** Grant **<ins>TOU</ins>**

This policy is based on the presumption that the minor risk stems from unintentional actions and prompts the minor insider risk user to accept the internal Terms of Use (TOU) before granting access. This gently reminds the user of the organization’s compliance standards and expected behavior. This utilizes awareness as a deterrent, subtly reinforcing security culture and ensuring at-risk individuals are conscious of their responsibilities, and actions, which in turn can dissuade negligent or unintentional risky behaviors.

You must create the Terms Of Use before configuring this policy. You can create a bare bones TOU, install the policy and then flesh out the TOU later if needed

### CA025-Global-IdentityProtection-AllApps-AnyPlatform-Block-Block High sign-in risk v1.0
This is set to **All Users** with **<ins>Breakglass</ins>** exclusion, Target resources **All resources**, Conditions Sign-in risk **High**, Grant **Block access**

CA102 applies MFA controls to admins. CA107 extends these controls with Password reset. CA022 requires MFA for Medium & High sign-in risk.

### CA026-Global-IdentityProtection-AllApps-AnyPlatform-Block-Block High user risk v1.0
This is set to **All Users** with **<ins>Breakglass</ins>** exclusion, Target resources **All resources**, Conditions User risk **High**, Grant **Block access**

CA102 applies MFA controls to admins. CA107 extends these controls with Password reset. CA022 requires MFA for Medium & High sign-in risk.

### CA806-Finance-AttackSurfaceReduction-AllApps-AnyPlatform-Block-Block Authentication Transfer for Finance v1.0
This is set to **<ins>Finance group</ins>** with **<ins>Breakglass</ins>** exclusion, Target resources **All resources**, Conditions Authentication Flows **Authentication Transfer**, Grant **Block access**

You will need to define the Finance group.