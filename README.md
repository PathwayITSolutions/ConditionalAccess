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

Default Settings are **in bold**. Settings you need to customize are ***underlined in bold***.

## Essentials

### CA000-Global-BaselineProtection-AllApps-AnyPlatform-Block-Block legacy authentication v1.0
This is set to **All Users** with no exclusions, Target resources **All resources**, Conditions Client apps **Exchange ActiveSync clients** and **Other clients**, Grant **Block access**

It is meant to be run without the Breakglass exception.

### CA001-Global-BaselineProtection-AllApps-AnyPlatform-MFA-Require MFA for all users v1.0
This is set to ***All Users group*** with ***Breakglass exclusion***, Target resources **All resources**, Grant access **Require authentication strength, Multifactor authentication strength**

### CA002-Global-AttackSurfaceReduction-AllApps-AnyPlatform-Block-Block non-business countries v1.0
This is set to ***All Users group*** with ***Breakglass exclusion***, Target resources **All resources**, Network Include Selected networks and locations ***Blocked access countries*** Exclude Selected entworks and locations ***Approved access countries***, Grant **Block access**

The Approved access countries and Blocked access countries lists need to be created in Microsoft Entra Named Locations before making this policy

### CA003-Global-DataProtection-AllApps-AnyPlatform-SessionControl-8H session lifetime for managed devices v1.0
This is set to **All Users** with no exclusions, Target resources **All resources**, Conditions Filter for devices Include filtered devices **device.deviceOwnership -eq "Company**, Grant **Sign-in frequency Periodic reauthentication 8 hours**

It is meant to be run without the Breakglass exception.

### CA004-Global-DataProtection-AllApps-AnyPlatform-SessionControl-3H session lifetime for unmanaged devices v1.0
This is set to **All Users** with no exclusions, Target resources **All resources**, Conditions Filter for devices Exclude filtered devices **device.deviceOwnership -eq "Company**, Grant **Sign-in frequency Periodic reauthentication 3 hours**

It is meant to be run without the Breakglass exception.

### CA005-Global-BaselineProtection-CombinedRegistration-AnyPlatform-MFA-Require MFA for registering security info v1.0
This is set to **All Users** with ***Guest or external users exclusion***, Target resources **User actions, register security information**, Grant **Require authentication strength, Multifactor authentication**

It is meant to be run without the Breakglass exception.

### CA006-Global-DeviceProtection-AllApps-WindowsPhone-Block-Block Unknown platforms v1.0
This is set to **All Users** with ***Breakglass exclusion***, Target resources **All resources**, Conditions Device platforms Include **Windows Phone** Exclude  **Android, iOS, Windows, macOS, Linux**, Grant **Block access**

### CA007-Global-Data&AppProtection-O365-iOS&Android-APP-Require App Protection Policy v1.0
This is set to **All Users** with ***Breakglass exclusion***, Target resources **Select resources, Office 365**, Conditions Device platforms Include **Android, iOS** Exclude  **WindowsPhone, Windows, macOS, Linux**, Grant **Require app protection policy**

Policies in Report-only mode requiring compliant devices may prompt users on macOS, iOS, Android, and Linux to select a device certificate.

### CA008-Global-DataProtection-AllApps-iOS&Android-Compliance-Require Compliance policy v1.0
This is set to **All Users** with ***Breakglass exclusion***, Target resources **Select resources, Office 365**, Conditions Device platforms Include **Android, iOS** Exclude  **WindowsPhone, Windows, macOS, Linux**, Grant **Require device to be marked as compliant**

### CA100-Admins-IdentityProtection-AllApps-AnyPlatform-AuthStr-Require Phishing-Resistant MFA for Admin roles v1.0
This is set to ***Select users and groups, Directory Roles*** with ***Breakglass exclusion***, Target resources **All resources**, Grant **Require authentication strength, Phishing-resistant MFA**

You will need to select the Directory Roles. I recommend everything Administrator, Editor, Technician, Engineer, Specialist, Creator, Security, Developer, Attribute, Writer, Inviter, Analyst, Author since all of these have some kind of write-access to the environment, or access privileged information

### CA400-Guests-BaselineProtection-AllApps-AnyPlatform-MFA-Require MFA for all guest users v1.0
This is set to **Select users and groups, Guest or external users** with ***Breakglass exclusion***, Target resources **All resources**, Grant **Require authentication strength, Multifactor authentication**

Select all guest and external users

### CA401-Guests-ComplianceProtection-CombinedRegistration-AnyPlatform-TOU-Require TOU for security info for Guests v1.0
This is set to **Select users and groups, Guest or external users** with ***Breakglass exclusion***, Target resources **Register security information**, Grant ***TOU***

Select all guest and external users

You must create the Terms Of Use before configuring this policy. You can create a bare bones TOU, install the policy and then flesh out the TOU later if needed

### CA900-Breakglass-IdentityProtection-AllApps-AnyPlatform-AuthStr-Require Phishing-resistant Authentication for BreakGlass Accounts v1.0
This is set to ***Breakglass account/group***, Target resources **All resources**, Grant **Require authentication strength, Phishing-resistant MFA**

Critical policy, as the Breakglass account/group is exempt from most of the other policies. It is a strong recommendation that Breakglass accounts are an onmicrosoft.com account with no licenses and Global Administrator role. A FIDO2 physical key with a PIN is the recommended authentication method, and ideally you will provision three Breakglass accounts, with one kept onsite in a safe with the login details, two kept offsite at different locations.

## Privileged Access

### CA101-Admins-AttackSurfaceReduction-iOS&Android-AllApps-Block-Block iOS & Android access v1.0
This is set to ***Select users and groups, Directory Roles*** with ***Breakglass exclusion***, Target resources **All resources**, Conditions Device platforms Include **Android, iOS** Exclude  **WindowsPhone, Windows, macOS, Linux**, Grant **Block access**

You will need to select the Directory Roles. I recommend everything Administrator, Editor, Technician, Engineer, Specialist, Creator, Security, Developer, Attribute, Writer, Inviter, Analyst, Author since all of these have some kind of write-access to the environment, or access privileged information

### CA102-Admins-IdentityProtection-AnyPlatform-AllApps-MFA-Require MFA for Medium & High risk Sign-in v1.0
This is set to ***Select users and groups, Directory Roles*** with ***Breakglass exclusion***, Target resources **All resources**, Conditions Sign-in risk **High, Medium**, Grant **Require authentication strength, Passwordless MFA**

CA022 applies similar controls to all users. CA107 extends these controls with Password reset. CA025 blocks High sign-in risk.

### CA103-Admins-DataProtection-AnyPlatform-AllApps-SessionControl-Non-persistent browser session & 4h frequency v1.0
This is set to ***Select users and groups, Directory Roles*** with ***Breakglass exclusion***, Target resources **All resources**, Session **Sign-in frequency Periodic reauthentication, 4 hours, Persistent browser session, Never persistent**

You will need to select the Directory Roles. I recommend everything Administrator, Editor, Technician, Engineer, Specialist, Creator, Security, Developer, Attribute, Writer, Inviter, Analyst, Author since all of these have some kind of write-access to the environment, or access privileged information

### CA104-Admins-DataProtection-AdminPortals-Windows&MacOS-Compliance&AuthStr-Require Compliant device & Phishing-resistant Auth for Admin Portals v1.0
This is set to ***Select users and groups, Directory Roles*** with ***Breakglass exclusion***, Target resources **Microsoft Admin Portals**, Conditions Device platforms Include **Windows, macOS** Exclude  **Android, iOS, WindowsPhone, Linux**, Grant **Require authentication strength, Phishing-resistant MFA, Require device to be marked as compliant** Require all the selected controls

You will need to select the Directory Roles. I recommend everything Administrator, Editor, Technician, Engineer, Specialist, Creator, Security, Developer, Attribute, Writer, Inviter, Analyst, Author since all of these have some kind of write-access to the environment, or access privileged information

Policies in Report-only mode requiring compliant devices may prompt users on macOS, iOS, Android, and Linux to select a device certificate.

### CA105-Admins-IdentityProtection-PIM-AnyPlatform-MFA-Require MFA for PIM elevation v1.0
This is set to ***Select users and groups, Directory Roles*** with ***Breakglass exclusion***, Target resources **Authentication context, c1**, Grant **Require authentication strength, Phishing-resistant MFA**, Session **Sign-in frequency, Every time**

You will need to select the Directory Roles. I recommend everything Administrator, Editor, Technician, Engineer, Specialist, Creator, Security, Developer, Attribute, Writer, Inviter, Analyst, Author since all of these have some kind of write-access to the environment, or access privileged information

Only available for creation if PIM is enabled

### CA106-Admins-AttackSurfaceReduction-O365-AnyPlatform-Block-Block access to Office 365 v1.
This is set to ***Select users and groups, Directory Roles*** with ***Breakglass exclusion***, Target resources **Office 365**, Grant **Block access**

You will need to select the Directory Roles. I recommend everything Administrator, Editor, Technician, Engineer, Specialist, Creator, Security, Developer, Attribute, Writer, Inviter, Analyst, Author since all of these have some kind of write-access to the environment, or access privileged information

### CA107-Admins-IdentityProtection-AnyPlatform-AllApps-MFA&PWDreset-Require MFA & Password reset for Medium & High user-risk v1.0
This is set to ***Select users and groups, Directory Roles*** with ***Breakglass exclusion***, Target resources **All resources**, Conditions User risk **High, Medium**, Grant **Require authentication strength, Passwordless MFA, Require password change** Require all the selected controls

You will need to select the Directory Roles. I recommend everything Administrator, Editor, Technician, Engineer, Specialist, Creator, Security, Developer, Attribute, Writer, Inviter, Analyst, Author since all of these have some kind of write-access to the environment, or access privileged information

CA022 applies similar controls to all users. CA102 mirrors these controls without Password reset. CA025 blocks High sign-in risk.

### CA500-GuestAdmins-AttackSurfaceReduction-O365-AnyPlatform-Block-Block access to Office 365 v1.0
TBD

### CA501-GuestAdmins-IdentityProtection-PIMelevation-AnyPlatform-MFA-Require MFA for PIM elevation v1.0
TBD

### CA502-GuestAdmins-IdentityProtection-AllApps-AnyPlatform-MFA&PWDreset-Require MFA & Password Reset for Medium & High user-risk Guest admins v1.0
TBD

### CA503-GuestAdmins-IdentityProtection-AllApps-AnyPlatform-MFA-Require MFA for Low+ sign-in risk for guest admins v1.0
TBD

### CA504-GuestAdmins-ComplianceProtection-CombinedRegistration-AnyPlatform-TOU-Require TOU for security info for Guest Admins v1.0
TBD

### CA505-GuestAdmins-DataProtection-AnyPlatform-AllApps-SessionControl-Non-persistent browser session & 1h frequency v1.0
TBD

## Application Policies

### CA009-Global-IdentityProtection-AllApps-AnyPlatform-CompliantNetwork-Require Global Secure Access client active v1.0
TBD

### CA010-Global-AttackSurfaceReduction-Exchange&Sharepoint-Windows-TokenProtection-Enforce Token Protection for Exchange & Sharepoint on Desktop applications v1.0
TBD

### CA011-Global-Data&AppProtection-O365-Windows-APP-Require App Protection Policy for Office 365 on the Web for Unmanaged Windows devices v1.0
TBD

### CA012-Global-Data&AppProtection-O365-AnyPlatform-AppRestriction-Enforce App Enforced Restrictions for Office 365 v1.0
TBD

### CA013-Global-Data&AppProtection-Exchange&Sharepoint-AnyPlatform-AppControl-Enforce Defender for Cloud Apps Session policy - Block Downloads for unmanaged devices v1.0
TBD

### CA014-Global-Data&AppProtection-VariousApps-AnyPlatform-AppControl-Enforce Defender for Cloud Apps Session policy - Custom policy v1.0
TBD

### CA015-Global-DataProtection-Sharepoint-AnyPlatform-ComplianceOREntraJoined-Require managed device for Sharepoint access v1.0
TBD

### CA016-Global-DataProtection-Sharepoint-AnyPlatform-AppControl-Enforce limited web access for Sharepoint for unmanaged device v1.0
TBD

### CA017-Global-IdentityProtection-AllApps-AnyPlatform-SessionControl-Enforce never persistent browser session v1.0
TBD

### CA901-Marketing-IdentityProtection-GSA-AnyPlatform-SecurityProfile-Enforce Entra Internet Access Security profile for Marketing v1.0
TBD

## Non-human identities

### CA800-ServiceAccounts-DataProtection-AllApps-AnyPlatform-Compliance-Require compliant device for untrusted networks for Service Accounts v1.0
TBD

### CA801-ServiceAccounts-AttackSurfaceReduction-AllApps-AnyPlatform-Block-Block untrusted locations v1.0
TBD

### CA802-ServiceAccounts-DataProtection-AllApps-AnyPlatform-Block-Enforce CAE strict location v1.0
TBD

### CA803-ServiceAccounts-IdentityProtection-AllApps-AnyPlatform-Block-Block Medium & High user risk v1.0
TBD

### CA804-ServiceAccounts-IdentityProtection-AllApps-AnyPlatform-Block-Block Medium & High sign-in risk v1.0
TBD

### CA805-ServiceAccounts-AttackSurfaceReduction-AllAppsExcludedMSFT-AnyPlatform-Block-Block unneeded applications v1.0
TBD

### CA902-WorkloadIDs-AttackSurfaceReduction-AllApps-AnyPlatform-Block-Block untrusted locations v1.0
TBD

### CA903-WorkloadIDs-IdentityProtection-AllApps-AnyPlatform-Block-Block Medium & High user risk v1.0
TBD

### CA904-WorkloadIDs-DataProtection-AllApps-AnyPlatform-Block-Enforce CAE strict location v1.0
TBD

## Risk-based

### CA018-Global-DataProtection-AllApps-AnyPlatform-Block-Block Elevated insider risk v1.0
TBD

### CA019-Global-DataProtection-O365-AnyPlatform-Block-Block business critical apps for Moderate insider risk v1.0
TBD

### CA020-Global-AttackSurfaceReduction-AllApps-AnyPlatform-Block-Block Device code flow v1.0
TBD

### CA021-Global-IdentityProtection-AllApps-AnyPlatform-MFA\u0026PWDreset-Require Password reset and MFA for High user risk v1.0
TBD

### CA022-Global-IdentityProtection-AllApps-AnyPlatform-MFA-Require MFA for Medium & High sign-in risk v1.0
TBD

CA102 applies similar controls to admins. CA107 extends these controls with Password reset. CA025 blocks High sign-in risk.

### CA023-Global-IdentityProtection-AllApps-AnyPlatform-MFA-Require MFA for Low \u0026 Medium user risk v1.0
TBD

### CA024-Global-ComplianceProtection-AllApps-AnyPlatform-TOU-Require TOU acceptance for Minor insider risk v1.0
TBD

### CA025-Global-IdentityProtection-AllApps-AnyPlatform-Block-Block High sign-in risk v1.0
TBD

CA102 applies MFA controls to admins. CA107 extends these controls with Password reset. CA022 requires MFA for Medium & High sign-in risk.

### CA026-Global-IdentityProtection-AllApps-AnyPlatform-Block-Block High user risk v1.0
TBD

### CA806-Finance-AttackSurfaceReduction-AllApps-AnyPlatform-Block-Block Authentication Transfer for Finance v1.0
TBD