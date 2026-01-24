# EzsignbulksendListElement

An Ezsignbulksend List Element

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**pkiEzsignbulksendID** | **number** | The unique ID of the Ezsignbulksend | [default to undefined]
**fkiEzsignfoldertypeID** | **number** | The unique ID of the Ezsignfoldertype. | [default to undefined]
**sEzsignbulksendDescription** | **string** | The description of the Ezsignbulksend | [default to undefined]
**sEzsignfoldertypeNameX** | **string** | The name of the Ezsignfoldertype in the language of the requester | [default to undefined]
**bEzsignbulksendNeedvalidation** | **boolean** | Whether the Ezsigntemplatepackage was automatically modified and needs a manual validation | [default to undefined]
**iEzsignbulksendtransmission** | **number** | The total number of Ezsignbulksendtransmissions in the Ezsignbulksend | [default to undefined]
**iEzsignfolder** | **number** | The total number of Ezsignfolders in the Ezsignbulksend | [default to undefined]
**iEzsigndocument** | **number** | The total number of Ezsigndocuments in the Ezsignbulksend | [default to undefined]
**iEzsignsignature** | **number** | The total number of Ezsignsignature in the Ezsignbulksend | [default to undefined]
**iEzsignsignatureSigned** | **number** | The total number of already signed Ezsignsignature blocks in the Ezsignbulksend | [default to undefined]
**bEzsignbulksendIsactive** | **boolean** | Whether the Ezsignbulksend is active or not | [default to undefined]

## Example

```typescript
import { EzsignbulksendListElement } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: EzsignbulksendListElement = {
    pkiEzsignbulksendID,
    fkiEzsignfoldertypeID,
    sEzsignbulksendDescription,
    sEzsignfoldertypeNameX,
    bEzsignbulksendNeedvalidation,
    iEzsignbulksendtransmission,
    iEzsignfolder,
    iEzsigndocument,
    iEzsignsignature,
    iEzsignsignatureSigned,
    bEzsignbulksendIsactive,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
