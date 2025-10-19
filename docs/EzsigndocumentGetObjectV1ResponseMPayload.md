# EzsigndocumentGetObjectV1ResponseMPayload

Payload for GET /1/object/ezsigndocument/{pkiEzsigndocumentID}

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**pkiEzsigndocumentID** | **number** | The unique ID of the Ezsigndocument | [default to undefined]
**fkiEzsignfolderID** | **number** | The unique ID of the Ezsignfolder | [default to undefined]
**fkiEzsignfoldersignerassociationIDDeclinedtosign** | **number** | The unique ID of the Ezsignfoldersignerassociation | [optional] [default to undefined]
**dtEzsigndocumentDuedate** | **string** | The maximum date and time at which the Ezsigndocument can be signed. | [default to undefined]
**dtEzsignformCompleted** | **string** | The date and time at which the Ezsignform has been completed. | [optional] [default to undefined]
**fkiLanguageID** | **number** | The unique ID of the Language.  Valid values:  |Value|Description| |-|-| |1|French| |2|English| | [optional] [default to undefined]
**sEzsigndocumentName** | **string** | The name of the document that will be presented to Ezsignfoldersignerassociations | [default to undefined]
**eEzsigndocumentStep** | [**FieldEEzsigndocumentStep**](FieldEEzsigndocumentStep.md) |  | [default to undefined]
**dtEzsigndocumentFirstsend** | **string** | The date and time when the Ezsigndocument was first sent. | [optional] [default to undefined]
**dtEzsigndocumentLastsend** | **string** | The date and time when the Ezsigndocument was sent the last time. | [optional] [default to undefined]
**iEzsigndocumentOrder** | **number** | The order in which the Ezsigndocument will be presented to the signatory in the Ezsignfolder. | [default to undefined]
**iEzsigndocumentPagetotal** | **number** | The number of pages in the Ezsigndocument. | [default to undefined]
**iEzsigndocumentSignaturesigned** | **number** | The number of signatures that were signed in the document. | [default to undefined]
**iEzsigndocumentSignaturetotal** | **number** | The number of total signatures that were requested in the Ezsigndocument. | [default to undefined]
**iEzsigndocumentFormfieldtotal** | **number** | The number of total Ezsignformfield that were requested in the Ezsigndocument. | [default to undefined]
**sEzsigndocumentMD5initial** | **string** | MD5 Hash of the initial PDF Document before signatures were applied to it. | [optional] [default to undefined]
**tEzsigndocumentDeclinedtosignreason** | **string** | A custom text message that will contain the refusal message if the Ezsigndocument is declined to sign | [optional] [default to undefined]
**sEzsigndocumentMD5signed** | **string** | MD5 Hash of the final PDF Document after all signatures were applied to it. | [optional] [default to undefined]
**bEzsigndocumentEzsignform** | **boolean** | If the Ezsigndocument contains an Ezsignform or not | [optional] [default to undefined]
**bEzsigndocumentHassignedsignatures** | **boolean** | If the Ezsigndocument contains signed signatures (From internal or external sources) | [optional] [default to undefined]
**bEzsigndocumentSendtoged** | **boolean** | Whether the Ezsigndocument was copied to EDM | [optional] [default to undefined]
**objAudit** | [**CommonAudit**](CommonAudit.md) |  | [optional] [default to undefined]
**sEzsigndocumentExternalid** | **string** | This field can be used to store an External ID from the client\&#39;s system.  Anything can be stored in this field, it will never be evaluated by the eZmax system and will be returned AS-IS.  To store multiple values, consider using a JSON formatted structure, a URL encoded string, a CSV or any other custom format.  | [optional] [default to undefined]
**iEzsigndocumentEzsignsignatureattachmenttotal** | **number** | The number of Ezsigndocumentattachment total | [default to undefined]
**iEzsigndocumentEzsigndiscussiontotal** | **number** | The total number of Ezsigndiscussions | [default to undefined]
**eEzsigndocumentSteptype** | [**ComputedEEzsigndocumentSteptype**](ComputedEEzsigndocumentSteptype.md) |  | [default to undefined]
**iEzsigndocumentStepformtotal** | **number** | The total number of steps in the form filling phase | [default to undefined]
**iEzsigndocumentStepformcurrent** | **number** | The current step in the form filling phase | [default to undefined]
**iEzsigndocumentStepsignaturetotal** | **number** | The total number of steps in the signature filling phase | [default to undefined]
**iEzsigndocumentStepsignatureCurrent** | **number** | The current step in the signature phase | [default to undefined]
**a_objEzsignfoldersignerassociationstatus** | [**Array&lt;CustomEzsignfoldersignerassociationstatusResponse&gt;**](CustomEzsignfoldersignerassociationstatusResponse.md) |  | [default to undefined]
**a_objEzsigndocumentdependency** | [**Array&lt;EzsigndocumentdependencyResponse&gt;**](EzsigndocumentdependencyResponse.md) |  | [optional] [default to undefined]

## Example

```typescript
import { EzsigndocumentGetObjectV1ResponseMPayload } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: EzsigndocumentGetObjectV1ResponseMPayload = {
    pkiEzsigndocumentID,
    fkiEzsignfolderID,
    fkiEzsignfoldersignerassociationIDDeclinedtosign,
    dtEzsigndocumentDuedate,
    dtEzsignformCompleted,
    fkiLanguageID,
    sEzsigndocumentName,
    eEzsigndocumentStep,
    dtEzsigndocumentFirstsend,
    dtEzsigndocumentLastsend,
    iEzsigndocumentOrder,
    iEzsigndocumentPagetotal,
    iEzsigndocumentSignaturesigned,
    iEzsigndocumentSignaturetotal,
    iEzsigndocumentFormfieldtotal,
    sEzsigndocumentMD5initial,
    tEzsigndocumentDeclinedtosignreason,
    sEzsigndocumentMD5signed,
    bEzsigndocumentEzsignform,
    bEzsigndocumentHassignedsignatures,
    bEzsigndocumentSendtoged,
    objAudit,
    sEzsigndocumentExternalid,
    iEzsigndocumentEzsignsignatureattachmenttotal,
    iEzsigndocumentEzsigndiscussiontotal,
    eEzsigndocumentSteptype,
    iEzsigndocumentStepformtotal,
    iEzsigndocumentStepformcurrent,
    iEzsigndocumentStepsignaturetotal,
    iEzsigndocumentStepsignatureCurrent,
    a_objEzsignfoldersignerassociationstatus,
    a_objEzsigndocumentdependency,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
