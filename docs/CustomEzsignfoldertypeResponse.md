# CustomEzsignfoldertypeResponse

A Custom Ezsignfoldertype Object

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**pkiEzsignfoldertypeID** | **number** | The unique ID of the Ezsignfoldertype. | [default to undefined]
**fkiFontIDAnnotation** | **number** | The unique ID of the Font | [optional] [default to undefined]
**fkiFontIDFormfield** | **number** | The unique ID of the Font | [optional] [default to undefined]
**fkiFontIDSignature** | **number** | The unique ID of the Font | [optional] [default to undefined]
**sEzsignfoldertypeNameX** | **string** | The name of the Ezsignfoldertype in the language of the requester | [optional] [default to undefined]
**bEzsignfoldertypeSendproofezsignsigner** | **boolean** | Whether we send the proof in the email to Ezsignsigner | [optional] [default to undefined]
**bEzsignfoldertypeAllowdownloadattachmentezsignsigner** | **boolean** | Whether we allow the Ezsigndocument to be downloaded by an Ezsignsigner | [optional] [default to undefined]
**bEzsignfoldertypeAllowdownloadproofezsignsigner** | **boolean** | Whether we allow the proof to be downloaded by an Ezsignsigner | [optional] [default to undefined]
**bEzsignfoldertypeAutomaticsignature** | **boolean** | Whether we allow the automatic signature by an User | [optional] [default to undefined]
**bEzsignfoldertypeDelegate** | **boolean** | Wheter if delegation of signature is allowed to another user or not | [optional] [default to undefined]
**bEzsignfoldertypeDiscussion** | **boolean** | Wheter if creating a new Discussion is allowed or not | [optional] [default to undefined]
**bEzsignfoldertypeReassignezsignsigner** | **boolean** | Wheter if Reassignment of signature is allowed by a signatory to another signatory or not | [optional] [default to undefined]
**bEzsignfoldertypeReassignuser** | **boolean** | Wheter if Reassignment of signature is allowed by a user to a signatory or another user or not | [optional] [default to undefined]
**bEzsignfoldertypeReassigngroup** | **boolean** | Wheter if Reassignment of signatures of the groups to which the user belongs is authorized by a user to himself | [optional] [default to undefined]
**iEzsignfoldertypeDeadlinedays** | **number** | The number of days to get all Ezsignsignatures | [optional] [default to undefined]
**iEzsignfoldertypeFontsizeannotation** | **number** | Font size for annotations | [optional] [default to undefined]
**iEzsignfoldertypeFontsizeformfield** | **number** | Font size for form fields | [optional] [default to undefined]
**eEzsignfoldertypeDocumentmerge** | [**FieldEEzsignfoldertypeDocumentmerge**](FieldEEzsignfoldertypeDocumentmerge.md) |  | [optional] [default to undefined]

## Example

```typescript
import { CustomEzsignfoldertypeResponse } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: CustomEzsignfoldertypeResponse = {
    pkiEzsignfoldertypeID,
    fkiFontIDAnnotation,
    fkiFontIDFormfield,
    fkiFontIDSignature,
    sEzsignfoldertypeNameX,
    bEzsignfoldertypeSendproofezsignsigner,
    bEzsignfoldertypeAllowdownloadattachmentezsignsigner,
    bEzsignfoldertypeAllowdownloadproofezsignsigner,
    bEzsignfoldertypeAutomaticsignature,
    bEzsignfoldertypeDelegate,
    bEzsignfoldertypeDiscussion,
    bEzsignfoldertypeReassignezsignsigner,
    bEzsignfoldertypeReassignuser,
    bEzsignfoldertypeReassigngroup,
    iEzsignfoldertypeDeadlinedays,
    iEzsignfoldertypeFontsizeannotation,
    iEzsignfoldertypeFontsizeformfield,
    eEzsignfoldertypeDocumentmerge,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
