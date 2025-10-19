# EzsignbulksendRequest

A Ezsignbulksend Object

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**pkiEzsignbulksendID** | **number** | The unique ID of the Ezsignbulksend | [optional] [default to undefined]
**fkiEzsignfoldertypeID** | **number** | The unique ID of the Ezsignfoldertype. | [default to undefined]
**fkiLanguageID** | **number** | The unique ID of the Language.  Valid values:  |Value|Description| |-|-| |1|French| |2|English| | [default to undefined]
**sEzsignbulksendDescription** | **string** | The description of the Ezsignbulksend | [default to undefined]
**tEzsignbulksendNote** | **string** | Note about the Ezsignbulksend | [default to undefined]
**bEzsignbulksendNeedvalidation** | **boolean** | Whether the Ezsigntemplatepackage was automatically modified and needs a manual validation | [default to undefined]
**bEzsignbulksendIsactive** | **boolean** | Whether the Ezsignbulksend is active or not | [default to undefined]

## Example

```typescript
import { EzsignbulksendRequest } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: EzsignbulksendRequest = {
    pkiEzsignbulksendID,
    fkiEzsignfoldertypeID,
    fkiLanguageID,
    sEzsignbulksendDescription,
    tEzsignbulksendNote,
    bEzsignbulksendNeedvalidation,
    bEzsignbulksendIsactive,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
