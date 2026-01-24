# EzsignfolderListElement

An Ezsignfolder List Element

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**pkiEzsignfolderID** | **number** | The unique ID of the Ezsignfolder | [default to undefined]
**fkiEzsignfoldertypeID** | **number** | The unique ID of the Ezsignfoldertype. | [default to undefined]
**eEzsignfoldertypePrivacylevel** | [**FieldEEzsignfoldertypePrivacylevel**](FieldEEzsignfoldertypePrivacylevel.md) |  | [default to undefined]
**sEzsignfoldertypeNameX** | **string** | The name of the Ezsignfoldertype in the language of the requester | [default to undefined]
**sEzsignfolderDescription** | **string** | The description of the Ezsignfolder | [default to undefined]
**eEzsignfolderStep** | [**FieldEEzsignfolderStep**](FieldEEzsignfolderStep.md) |  | [default to undefined]
**eEzsignfolderCompletion** | [**FieldEEzsignfolderCompletion**](FieldEEzsignfolderCompletion.md) |  | [default to undefined]
**dtCreatedDate** | **string** | The date and time at which the object was created | [default to undefined]
**dtEzsignfolderDelayedsenddate** | **string** | The date and time at which the Ezsignfolder will be sent in the future. | [optional] [default to undefined]
**dtEzsignfolderSentdate** | **string** | The date and time at which the Ezsignfolder was sent the last time. | [optional] [default to undefined]
**dtEzsignfolderDuedate** | **string** | The maximum date and time at which the Ezsignfolder can be signed. | [optional] [default to undefined]
**iEzsigndocument** | **number** | The total number of Ezsigndocument in the folder | [default to undefined]
**iEzsigndocumentEdm** | **number** | The total number of Ezsigndocument in the folder that were saved in the edm system | [default to undefined]
**iEzsignsignature** | **number** | The total number of signature blocks in all Ezsigndocuments in the folder | [default to undefined]
**iEzsignsignatureSigned** | **number** | The total number of already signed signature blocks in all Ezsigndocuments in the folder | [default to undefined]
**iEzsignformfieldgroup** | **number** | The total number of Ezsignformfieldgroup in all Ezsigndocuments in the folder | [default to undefined]
**iEzsignformfieldgroupCompleted** | **number** | The total number of completed Ezsignformfieldgroup in all Ezsigndocuments in the folder | [default to undefined]
**bEzsignformHasdependencies** | **boolean** | Whether the Ezsignform/Ezsignsignatures has dependencies or not | [optional] [default to undefined]
**dEzsignfolderCompletedpercentage** | **string** | Percentage of Ezsignform/Ezsignsignatures has completed | [default to undefined]
**dEzsignfolderFormcompletedpercentage** | **string** | Percentage of Ezsignform has completed | [default to undefined]
**dEzsignfolderSignaturecompletedpercentage** | **string** | Percentage of Ezsignsignatures has signed | [default to undefined]
**dtEzsignfolderClose** | **string** | The date and time at which the Ezsignfolder was closed. Either by applying the last signature or by completing it prematurely. | [optional] [default to undefined]
**dtEzsignfolderArchive** | **string** | The date and time at which the Ezsignfolder was archived. | [optional] [default to undefined]
**dtEzsignfolderDispose** | **string** | The date and time at which the Ezsignfolder was disposed. | [optional] [default to undefined]
**bEzsignfolderSigner** | **boolean** | Whether the Ezsignfolder has an Ezsignsignatures that need to be signed or an Ezsignformfieldgroups that need to be filled by the current user | [optional] [default to undefined]

## Example

```typescript
import { EzsignfolderListElement } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: EzsignfolderListElement = {
    pkiEzsignfolderID,
    fkiEzsignfoldertypeID,
    eEzsignfoldertypePrivacylevel,
    sEzsignfoldertypeNameX,
    sEzsignfolderDescription,
    eEzsignfolderStep,
    eEzsignfolderCompletion,
    dtCreatedDate,
    dtEzsignfolderDelayedsenddate,
    dtEzsignfolderSentdate,
    dtEzsignfolderDuedate,
    iEzsigndocument,
    iEzsigndocumentEdm,
    iEzsignsignature,
    iEzsignsignatureSigned,
    iEzsignformfieldgroup,
    iEzsignformfieldgroupCompleted,
    bEzsignformHasdependencies,
    dEzsignfolderCompletedpercentage,
    dEzsignfolderFormcompletedpercentage,
    dEzsignfolderSignaturecompletedpercentage,
    dtEzsignfolderClose,
    dtEzsignfolderArchive,
    dtEzsignfolderDispose,
    bEzsignfolderSigner,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
