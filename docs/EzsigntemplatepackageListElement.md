# EzsigntemplatepackageListElement

An Ezsigntemplatepackage List Element

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**pkiEzsigntemplatepackageID** | **number** | The unique ID of the Ezsigntemplatepackage | [default to undefined]
**fkiEzsignfoldertypeID** | **number** | The unique ID of the Ezsignfoldertype. | [default to undefined]
**fkiLanguageID** | **number** | The unique ID of the Language.  Valid values:  |Value|Description| |-|-| |1|French| |2|English| | [default to undefined]
**sEzsigntemplatepackageDescription** | **string** | The description of the Ezsigntemplatepackage | [default to undefined]
**bEzsigntemplatepackageNeedvalidation** | **boolean** | Whether the Ezsignbulksend was automatically modified and needs a manual validation | [default to undefined]
**iEzsigntemplatepackagemembership** | **number** | The total number of Ezsigntemplatepackagemembership in the Ezsigntemplatepackage | [default to undefined]
**sEzsignfoldertypeNameX** | **string** | The name of the Ezsignfoldertype in the language of the requester | [default to undefined]
**bEzsigntemplatepackageIsactive** | **boolean** | Whether the Ezsigntemplatepackage is active or not | [default to undefined]

## Example

```typescript
import { EzsigntemplatepackageListElement } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: EzsigntemplatepackageListElement = {
    pkiEzsigntemplatepackageID,
    fkiEzsignfoldertypeID,
    fkiLanguageID,
    sEzsigntemplatepackageDescription,
    bEzsigntemplatepackageNeedvalidation,
    iEzsigntemplatepackagemembership,
    sEzsignfoldertypeNameX,
    bEzsigntemplatepackageIsactive,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
