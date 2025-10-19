# EzsignfoldertypeResponse

A Ezsignfoldertype Object

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**pkiEzsignfoldertypeID** | **number** | The unique ID of the Ezsignfoldertype. | [default to undefined]
**objEzsignfoldertypeName** | [**MultilingualEzsignfoldertypeName**](MultilingualEzsignfoldertypeName.md) |  | [default to undefined]
**fkiBrandingID** | **number** | The unique ID of the Branding | [default to undefined]
**fkiBillingentityinternalID** | **number** | The unique ID of the Billingentityinternal. | [optional] [default to undefined]
**fkiUsergroupID** | **number** | The unique ID of the Usergroup | [optional] [default to undefined]
**fkiUsergroupIDRestricted** | **number** | The unique ID of the Usergroup | [optional] [default to undefined]
**fkiEzsigntsarequirementID** | **number** | The unique ID of the Ezsigntsarequirement.  Determine if a Time Stamping Authority should add a timestamp on each of the signature. Valid values:  |Value|Description| |-|-| |1|No. TSA Timestamping will requested. This will make all signatures a lot faster since no round-trip to the TSA server will be required. Timestamping will be made using eZsign server\&#39;s time.| |2|Best effort. Timestamping from a Time Stamping Authority will be requested but is not mandatory. In the very improbable case it cannot be completed, the timestamping will be made using eZsign server\&#39;s time. **Additional fee applies**| |3|Mandatory. Timestamping from a Time Stamping Authority will be requested and is mandatory. In the very improbable case it cannot be completed, the signature will fail and the user will be asked to retry. **Additional fee applies**| | [optional] [default to undefined]
**sBrandingDescriptionX** | **string** | The Description of the Branding in the language of the requester | [default to undefined]
**sBillingentityinternalDescriptionX** | **string** | The description of the Billingentityinternal in the language of the requester | [optional] [default to undefined]
**sEzsigntsarequirementDescriptionX** | **string** | The description of the Ezsigntsarequirement in the language of the requester | [optional] [default to undefined]
**sEmailAddressSigned** | **string** | The email address. | [optional] [default to undefined]
**sEmailAddressSummary** | **string** | The email address. | [optional] [default to undefined]
**sUsergroupNameX** | **string** | The Name of the Usergroup in the language of the requester | [optional] [default to undefined]
**sUsergroupNameXRestricted** | **string** | The Name of the Usergroup in the language of the requester | [optional] [default to undefined]
**eEzsignfoldertypePrivacylevel** | [**FieldEEzsignfoldertypePrivacylevel**](FieldEEzsignfoldertypePrivacylevel.md) |  | [default to undefined]
**eEzsignfoldertypeSendreminderfrequency** | [**FieldEEzsignfoldertypeSendreminderfrequency**](FieldEEzsignfoldertypeSendreminderfrequency.md) |  | [optional] [default to undefined]
**iEzsignfoldertypeArchivaldays** | **number** | The number of days before the archival of Ezsignfolders created using this Ezsignfoldertype | [default to undefined]
**eEzsignfoldertypeDisposal** | [**FieldEEzsignfoldertypeDisposal**](FieldEEzsignfoldertypeDisposal.md) |  | [default to undefined]
**eEzsignfoldertypeCompletion** | [**FieldEEzsignfoldertypeCompletion**](FieldEEzsignfoldertypeCompletion.md) |  | [default to undefined]
**iEzsignfoldertypeDisposaldays** | **number** | The number of days after the archival before the disposal of the Ezsignfolder | [optional] [default to undefined]
**iEzsignfoldertypeDeadlinedays** | **number** | The number of days to get all Ezsignsignatures | [default to undefined]
**bEzsignfoldertypeAutomaticsignature** | **boolean** | Whether we allow the automatic signature by an User | [optional] [default to undefined]
**bEzsignfoldertypeDelegate** | **boolean** | Wheter if delegation of signature is allowed to another user or not | [optional] [default to undefined]
**bEzsignfoldertypeDiscussion** | **boolean** | Wheter if creating a new Discussion is allowed or not | [optional] [default to undefined]
**bEzsignfoldertypeReassignezsignsigner** | **boolean** | Wheter if Reassignment of signature is allowed by a signatory to another signatory or not | [optional] [default to undefined]
**bEzsignfoldertypeReassignuser** | **boolean** | Wheter if Reassignment of signature is allowed by a user to a signatory or another user or not | [optional] [default to undefined]
**bEzsignfoldertypeReassigngroup** | **boolean** | Wheter if Reassignment of signatures of the groups to which the user belongs is authorized by a user to himself | [optional] [default to undefined]
**bEzsignfoldertypeSendsignedtoezsignsigner** | **boolean** | Whether we send an email to Ezsignsigner  when document is completed | [optional] [default to undefined]
**bEzsignfoldertypeSendsignedtouser** | **boolean** | Whether we send an email to User who signed when document is completed | [optional] [default to undefined]
**bEzsignfoldertypeSendattachmentezsignsigner** | **boolean** | Whether we send the Ezsigndocument in the email to Ezsignsigner | [optional] [default to undefined]
**bEzsignfoldertypeSendproofezsignsigner** | **boolean** | Whether we send the proof in the email to Ezsignsigner | [optional] [default to undefined]
**bEzsignfoldertypeSendattachmentuser** | **boolean** | Whether we send the Ezsigndocument in the email to User | [optional] [default to undefined]
**bEzsignfoldertypeSendproofuser** | **boolean** | Whether we send the proof in the email to User | [optional] [default to undefined]
**bEzsignfoldertypeSendproofemail** | **boolean** | Whether we send the proof in the email to external recipient | [optional] [default to undefined]
**bEzsignfoldertypeAllowdownloadattachmentezsignsigner** | **boolean** | Whether we allow the Ezsigndocument to be downloaded by an Ezsignsigner | [optional] [default to undefined]
**bEzsignfoldertypeAllowdownloadproofezsignsigner** | **boolean** | Whether we allow the proof to be downloaded by an Ezsignsigner | [optional] [default to undefined]
**bEzsignfoldertypeSendproofreceivealldocument** | **boolean** | Whether we send the proof to user and Ezsignsigner who receive all documents. | [optional] [default to undefined]
**bEzsignfoldertypeSendsignedtodocumentowner** | **boolean** | Whether we send the signed Ezsigndocument to the Ezsigndocument\&#39;s owner | [default to undefined]
**bEzsignfoldertypeSendsignedtofolderowner** | **boolean** | Whether we send the signed Ezsigndocument to the Ezsignfolder\&#39;s owner | [default to undefined]
**bEzsignfoldertypeSendsignedtofullgroup** | **boolean** | Whether we send the signed Ezsigndocument to the Usergroup that has acces to all Ezsignfolders | [optional] [default to undefined]
**bEzsignfoldertypeSendsignedtolimitedgroup** | **boolean** | THIS FIELD WILL BE DELETED. Whether we send the signed Ezsigndocument to the Usergroup that has acces to only their own Ezsignfolders | [optional] [default to undefined]
**bEzsignfoldertypeSendsignedtocolleague** | **boolean** | Whether we send the signed Ezsigndocument to the colleagues | [default to undefined]
**bEzsignfoldertypeSendsummarytodocumentowner** | **boolean** | Whether we send the summary to the Ezsigndocument\&#39;s owner | [default to undefined]
**bEzsignfoldertypeSendsummarytofolderowner** | **boolean** | Whether we send the summary to the Ezsignfolder\&#39;s owner | [default to undefined]
**bEzsignfoldertypeSendsummarytofullgroup** | **boolean** | Whether we send the summary to the Usergroup that has acces to all Ezsignfolders | [optional] [default to undefined]
**bEzsignfoldertypeSendsummarytolimitedgroup** | **boolean** | Whether we send the summary to the Usergroup that has acces to only their own Ezsignfolders | [optional] [default to undefined]
**bEzsignfoldertypeSendsummarytocolleague** | **boolean** | Whether we send the summary to the colleagues | [default to undefined]
**bEzsignfoldertypeIsactive** | **boolean** | Whether the Ezsignfoldertype is active or not | [default to undefined]
**a_objUserlogintype** | [**Array&lt;UserlogintypeResponse&gt;**](UserlogintypeResponse.md) |  | [default to undefined]

## Example

```typescript
import { EzsignfoldertypeResponse } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: EzsignfoldertypeResponse = {
    pkiEzsignfoldertypeID,
    objEzsignfoldertypeName,
    fkiBrandingID,
    fkiBillingentityinternalID,
    fkiUsergroupID,
    fkiUsergroupIDRestricted,
    fkiEzsigntsarequirementID,
    sBrandingDescriptionX,
    sBillingentityinternalDescriptionX,
    sEzsigntsarequirementDescriptionX,
    sEmailAddressSigned,
    sEmailAddressSummary,
    sUsergroupNameX,
    sUsergroupNameXRestricted,
    eEzsignfoldertypePrivacylevel,
    eEzsignfoldertypeSendreminderfrequency,
    iEzsignfoldertypeArchivaldays,
    eEzsignfoldertypeDisposal,
    eEzsignfoldertypeCompletion,
    iEzsignfoldertypeDisposaldays,
    iEzsignfoldertypeDeadlinedays,
    bEzsignfoldertypeAutomaticsignature,
    bEzsignfoldertypeDelegate,
    bEzsignfoldertypeDiscussion,
    bEzsignfoldertypeReassignezsignsigner,
    bEzsignfoldertypeReassignuser,
    bEzsignfoldertypeReassigngroup,
    bEzsignfoldertypeSendsignedtoezsignsigner,
    bEzsignfoldertypeSendsignedtouser,
    bEzsignfoldertypeSendattachmentezsignsigner,
    bEzsignfoldertypeSendproofezsignsigner,
    bEzsignfoldertypeSendattachmentuser,
    bEzsignfoldertypeSendproofuser,
    bEzsignfoldertypeSendproofemail,
    bEzsignfoldertypeAllowdownloadattachmentezsignsigner,
    bEzsignfoldertypeAllowdownloadproofezsignsigner,
    bEzsignfoldertypeSendproofreceivealldocument,
    bEzsignfoldertypeSendsignedtodocumentowner,
    bEzsignfoldertypeSendsignedtofolderowner,
    bEzsignfoldertypeSendsignedtofullgroup,
    bEzsignfoldertypeSendsignedtolimitedgroup,
    bEzsignfoldertypeSendsignedtocolleague,
    bEzsignfoldertypeSendsummarytodocumentowner,
    bEzsignfoldertypeSendsummarytofolderowner,
    bEzsignfoldertypeSendsummarytofullgroup,
    bEzsignfoldertypeSendsummarytolimitedgroup,
    bEzsignfoldertypeSendsummarytocolleague,
    bEzsignfoldertypeIsactive,
    a_objUserlogintype,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
