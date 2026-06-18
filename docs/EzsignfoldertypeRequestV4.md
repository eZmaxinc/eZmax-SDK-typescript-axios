# EzsignfoldertypeRequestV4

A Ezsignfoldertype Object

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**pkiEzsignfoldertypeID** | **number** | The unique ID of the Ezsignfoldertype. | [optional] [default to undefined]
**objEzsignfoldertypeName** | [**MultilingualEzsignfoldertypeName**](MultilingualEzsignfoldertypeName.md) |  | [default to undefined]
**fkiBrandingID** | **number** | The unique ID of the Branding | [default to undefined]
**fkiBillingentityinternalID** | **number** | The unique ID of the Billingentityinternal. | [optional] [default to undefined]
**fkiEzsigntsarequirementID** | **number** | The unique ID of the Ezsigntsarequirement.  Determine if a Time Stamping Authority should add a timestamp on each of the signature. Valid values:  |Value|Description| |-|-| |1|No. TSA Timestamping will requested. This will make all signatures a lot faster since no round-trip to the TSA server will be required. Timestamping will be made using eZsign server\&#39;s time.| |2|Best effort. Timestamping from a Time Stamping Authority will be requested but is not mandatory. In the very improbable case it cannot be completed, the timestamping will be made using eZsign server\&#39;s time. **Additional fee applies**| |3|Mandatory. Timestamping from a Time Stamping Authority will be requested and is mandatory. In the very improbable case it cannot be completed, the signature will fail and the user will be asked to retry. **Additional fee applies**| | [optional] [default to undefined]
**fkiFontIDAnnotation** | **number** | The unique ID of the Font | [optional] [default to undefined]
**fkiFontIDFormfield** | **number** | The unique ID of the Font | [optional] [default to undefined]
**fkiFontIDSignature** | **number** | The unique ID of the Font | [optional] [default to undefined]
**fkiPdfalevelIDConvert** | **number** | The unique ID of the Pdfalevel | [optional] [default to undefined]
**a_fkiPdfalevelID** | **Array&lt;number&gt;** |  | [optional] [default to undefined]
**a_fkiUserlogintypeID** | **Array&lt;number&gt;** |  | [default to undefined]
**a_fkiUsergroupIDAll** | **Array&lt;number&gt;** |  | [optional] [default to undefined]
**a_fkiUsergroupIDRestricted** | **Array&lt;number&gt;** |  | [optional] [default to undefined]
**a_fkiUsergroupIDTemplate** | **Array&lt;number&gt;** |  | [optional] [default to undefined]
**eEzsignfoldertypeSignaturedatedisplay** | [**FieldEEzsignfoldertypeSignaturedatedisplay**](FieldEEzsignfoldertypeSignaturedatedisplay.md) |  | [default to undefined]
**sEzsignfoldertypeSignaturedatecustomformat** | **string** | The custom date format to use  You can use the codes below and they will be replaced at signature time. Text values like month and day names will be rendered in the proper language. Other text will be left as-is.  The codes examples below are based on the following datetime: Thursday, January 6, 2022 at 08:07:09 EST  For example, the format \&quot;Signature date: {MM}/{DD}/{YYYY} {hh}:{mm}\&quot; would become \&quot;Signature date: 01/06/2022 08:07\&quot;  **Year**  | Code | Example | | - | - | | {YYYY} | 2022 | | {YY} | 22 |  **Month**  | Code | Example | | - | - | | {MonthCapitalize} | Janvier | | {Month} | janvier | | {MM} | 01 | | {M} | 1 |  **Day**  | Code | Example | | - | - | | {DayCapitalize} | Jeudi | | {Day} | jeudi | | {DD} | 06 | | {D} | 6 |  **Hour**  | Code | Example | | - | - | | {hh} | 08 |  **Minute**  | Code | Example | | - | - | | {mm} | 07 |  **Second**  | Code | Example | | - | - | | {ss} | 09 |        **Timezone**  | Code | Example | | - | - | | {Z} | EST |       **Time**  | Code | Example | | - | - | | {Time} | 08:07:09 |   | {TimeZ} | 08:07:09 EST |     **Date**  | Code | Example | | - | - | | {Date} | 2022-01-06 |   | {DateText} | 1er Janvier 2022 |  **Full**  | Code | Example | | - | - | | {DateTime} | 2022-01-06 08:07:09 |   | {DateTimeZ} | 2022-01-06 08:07:09 EST |  | [optional] [default to undefined]
**eEzsignfoldertypeDocumentdependency** | [**FieldEEzsignfoldertypeDocumentdependency**](FieldEEzsignfoldertypeDocumentdependency.md) |  | [optional] [default to undefined]
**eEzsignfoldertypeDocumentmerge** | [**FieldEEzsignfoldertypeDocumentmerge**](FieldEEzsignfoldertypeDocumentmerge.md) |  | [optional] [default to undefined]
**sEmailAddressSigned** | **string** | The email address. | [optional] [default to undefined]
**sEmailAddressSummary** | **string** | The email address. | [optional] [default to undefined]
**eEzsignfoldertypePdfarequirement** | [**FieldEEzsignfoldertypePdfarequirement**](FieldEEzsignfoldertypePdfarequirement.md) |  | [optional] [default to undefined]
**eEzsignfoldertypePdfanoncompliantaction** | [**FieldEEzsignfoldertypePdfanoncompliantaction**](FieldEEzsignfoldertypePdfanoncompliantaction.md) |  | [optional] [default to undefined]
**eEzsignfoldertypePrivacylevel** | [**FieldEEzsignfoldertypePrivacylevel**](FieldEEzsignfoldertypePrivacylevel.md) |  | [default to undefined]
**iEzsignfoldertypeFontsizeannotation** | **number** | Font size for annotations | [optional] [default to undefined]
**iEzsignfoldertypeFontsizeformfield** | **number** | Font size for form fields | [optional] [default to undefined]
**iEzsignfoldertypeSendreminderfirstdays** | **number** | The number of days before the first reminder sending | [optional] [default to undefined]
**iEzsignfoldertypeSendreminderotherdays** | **number** | The number of days after the first reminder sending | [optional] [default to undefined]
**iEzsignfoldertypeArchivaldays** | **number** | The number of days before the archival of Ezsignfolders created using this Ezsignfoldertype | [default to undefined]
**eEzsignfoldertypeDisposal** | [**FieldEEzsignfoldertypeDisposal**](FieldEEzsignfoldertypeDisposal.md) |  | [default to undefined]
**eEzsignfoldertypeCompletion** | [**FieldEEzsignfoldertypeCompletion**](FieldEEzsignfoldertypeCompletion.md) |  | [default to undefined]
**iEzsignfoldertypeDisposaldays** | **number** | The number of days after the archival before the disposal of the Ezsignfolder | [optional] [default to undefined]
**iEzsignfoldertypeDeadlinedays** | **number** | The number of days to get all Ezsignsignatures | [default to undefined]
**bEzsignfoldertypePrematurelyendautomatically** | **boolean** | Wheter if document will be ended prematurely after Ezsignfolder expires. | [optional] [default to undefined]
**iEzsignfoldertypePrematurelyendautomaticallydays** | **number** | Number of days between Ezsignfolder expiration and automatic prematurely end of Ezsigndocuments. | [optional] [default to undefined]
**bEzsignfoldertypeAutomaticsignature** | **boolean** | Whether we allow the automatic signature by an User | [optional] [default to undefined]
**bEzsignfoldertypeDelegate** | **boolean** | Wheter if delegation of signature is allowed to another user or not | [optional] [default to undefined]
**bEzsignfoldertypeDiscussion** | **boolean** | Wheter if creating a new Discussion is allowed or not | [optional] [default to undefined]
**bEzsignfoldertypeLogrecipientinproof** | **boolean** | Whether we log recipient of signed document in proof | [optional] [default to undefined]
**bEzsignfoldertypeReassignezsignsigner** | **boolean** | Wheter if Reassignment of signature is allowed by a signatory to another signatory or not | [optional] [default to undefined]
**bEzsignfoldertypeReassignuser** | **boolean** | Wheter if Reassignment of signature is allowed by a user to a signatory or another user or not | [optional] [default to undefined]
**bEzsignfoldertypeReassigngroup** | **boolean** | Wheter if Reassignment of signatures of the groups to which the user belongs is authorized by a user to himself | [optional] [default to undefined]
**bEzsignfoldertypeSenddocumentmergetoemail** | **boolean** | Whether we send the merged documents in the email to external recipient | [optional] [default to undefined]
**bEzsignfoldertypeSenddocumentmergetoezsignsigner** | **boolean** | Whether we send the merged documents in the email to Ezsignsigner | [optional] [default to undefined]
**bEzsignfoldertypeSenddocumentmergetoreceivealldocument** | **boolean** | Whether we send the merged documents in the email to user and Ezsignsigner who receive all documents. | [optional] [default to undefined]
**bEzsignfoldertypeSenddocumentmergetouser** | **boolean** | Whether we send the merged documents in the email to User | [optional] [default to undefined]
**bEzsignfoldertypeSendsignedtoezsignsigner** | **boolean** | Whether we send an email to Ezsignsigner  when document is completed | [optional] [default to undefined]
**bEzsignfoldertypeSendsignedtouser** | **boolean** | Whether we send an email to User who signed when document is completed | [optional] [default to undefined]
**bEzsignfoldertypeSendattachmentezsignsigner** | **boolean** | Whether we send the Ezsigndocument in the email to Ezsignsigner | [optional] [default to undefined]
**bEzsignfoldertypeSendsignatureattachmentezsignsigner** | **boolean** | Whether we send the attachments contained in the Ezsignsignatures in the email to Ezsignsigner | [optional] [default to undefined]
**bEzsignfoldertypeSendsignatureattachment** | **boolean** | Whether we send the attachments contained in the Ezsignsignatures in the email to external recipient | [optional] [default to undefined]
**bEzsignfoldertypeSendproofezsignsigner** | **boolean** | Whether we send the proof in the email to Ezsignsigner | [optional] [default to undefined]
**bEzsignfoldertypeSendattachmentuser** | **boolean** | Whether we send the Ezsigndocument in the email to User | [optional] [default to undefined]
**bEzsignfoldertypeSendsignatureattachmentuser** | **boolean** | Whether we send the attachments contained in the Ezsignsignatures in the email to User | [optional] [default to undefined]
**bEzsignfoldertypeSendproofuser** | **boolean** | Whether we send the proof in the email to User | [optional] [default to undefined]
**bEzsignfoldertypeSendproofemail** | **boolean** | Whether we send the proof in the email to external recipient | [optional] [default to undefined]
**bEzsignfoldertypeAllowdownloadattachmentezsignsigner** | **boolean** | Whether we allow the Ezsigndocument to be downloaded by an Ezsignsigner | [optional] [default to undefined]
**bEzsignfoldertypeAllowdownloadsignatureattachmentezsignsigner** | **boolean** | Whether we allow the attachments in the Ezsignsignatures to be downloaded by an Ezsignsigner | [optional] [default to undefined]
**bEzsignfoldertypeAllowdownloadproofezsignsigner** | **boolean** | Whether we allow the proof to be downloaded by an Ezsignsigner | [optional] [default to undefined]
**bEzsignfoldertypeSendproofreceivealldocument** | **boolean** | Whether we send the proof to user and Ezsignsigner who receive all documents. | [optional] [default to undefined]
**bEzsignfoldertypeSendsignatureattachmentreceivealldocument** | **boolean** | Whether we send the attachments contained in the Ezsignsignatures to user and Ezsignsigner who receive all documents. | [optional] [default to undefined]
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
**eEzsignfoldertypeSigneraccess** | [**FieldEEzsignfoldertypeSigneraccess**](FieldEEzsignfoldertypeSigneraccess.md) |  | [optional] [default to undefined]
**bEzsignfoldertypeIsactive** | **boolean** | Whether the Ezsignfoldertype is active or not | [default to undefined]

## Example

```typescript
import { EzsignfoldertypeRequestV4 } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: EzsignfoldertypeRequestV4 = {
    pkiEzsignfoldertypeID,
    objEzsignfoldertypeName,
    fkiBrandingID,
    fkiBillingentityinternalID,
    fkiEzsigntsarequirementID,
    fkiFontIDAnnotation,
    fkiFontIDFormfield,
    fkiFontIDSignature,
    fkiPdfalevelIDConvert,
    a_fkiPdfalevelID,
    a_fkiUserlogintypeID,
    a_fkiUsergroupIDAll,
    a_fkiUsergroupIDRestricted,
    a_fkiUsergroupIDTemplate,
    eEzsignfoldertypeSignaturedatedisplay,
    sEzsignfoldertypeSignaturedatecustomformat,
    eEzsignfoldertypeDocumentdependency,
    eEzsignfoldertypeDocumentmerge,
    sEmailAddressSigned,
    sEmailAddressSummary,
    eEzsignfoldertypePdfarequirement,
    eEzsignfoldertypePdfanoncompliantaction,
    eEzsignfoldertypePrivacylevel,
    iEzsignfoldertypeFontsizeannotation,
    iEzsignfoldertypeFontsizeformfield,
    iEzsignfoldertypeSendreminderfirstdays,
    iEzsignfoldertypeSendreminderotherdays,
    iEzsignfoldertypeArchivaldays,
    eEzsignfoldertypeDisposal,
    eEzsignfoldertypeCompletion,
    iEzsignfoldertypeDisposaldays,
    iEzsignfoldertypeDeadlinedays,
    bEzsignfoldertypePrematurelyendautomatically,
    iEzsignfoldertypePrematurelyendautomaticallydays,
    bEzsignfoldertypeAutomaticsignature,
    bEzsignfoldertypeDelegate,
    bEzsignfoldertypeDiscussion,
    bEzsignfoldertypeLogrecipientinproof,
    bEzsignfoldertypeReassignezsignsigner,
    bEzsignfoldertypeReassignuser,
    bEzsignfoldertypeReassigngroup,
    bEzsignfoldertypeSenddocumentmergetoemail,
    bEzsignfoldertypeSenddocumentmergetoezsignsigner,
    bEzsignfoldertypeSenddocumentmergetoreceivealldocument,
    bEzsignfoldertypeSenddocumentmergetouser,
    bEzsignfoldertypeSendsignedtoezsignsigner,
    bEzsignfoldertypeSendsignedtouser,
    bEzsignfoldertypeSendattachmentezsignsigner,
    bEzsignfoldertypeSendsignatureattachmentezsignsigner,
    bEzsignfoldertypeSendsignatureattachment,
    bEzsignfoldertypeSendproofezsignsigner,
    bEzsignfoldertypeSendattachmentuser,
    bEzsignfoldertypeSendsignatureattachmentuser,
    bEzsignfoldertypeSendproofuser,
    bEzsignfoldertypeSendproofemail,
    bEzsignfoldertypeAllowdownloadattachmentezsignsigner,
    bEzsignfoldertypeAllowdownloadsignatureattachmentezsignsigner,
    bEzsignfoldertypeAllowdownloadproofezsignsigner,
    bEzsignfoldertypeSendproofreceivealldocument,
    bEzsignfoldertypeSendsignatureattachmentreceivealldocument,
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
    eEzsignfoldertypeSigneraccess,
    bEzsignfoldertypeIsactive,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
