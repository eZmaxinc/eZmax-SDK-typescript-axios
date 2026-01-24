# EzsigntemplateListElement

A Ezsigntemplate List Element

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**pkiEzsigntemplateID** | **number** | The unique ID of the Ezsigntemplate | [default to undefined]
**fkiEzsignfoldertypeID** | **number** | The unique ID of the Ezsignfoldertype. | [optional] [default to undefined]
**fkiLanguageID** | **number** | The unique ID of the Language.  Valid values:  |Value|Description| |-|-| |1|French| |2|English| | [default to undefined]
**sEzsigntemplateDescription** | **string** | The description of the Ezsigntemplate | [default to undefined]
**iEzsigntemplatedocumentPagetotal** | **number** | The number of pages in the Ezsigntemplatedocument. | [optional] [default to undefined]
**iEzsigntemplateSignaturetotal** | **number** | The number of total signatures in the Ezsigntemplate. | [optional] [default to undefined]
**iEzsigntemplateFormfieldtotal** | **number** | The number of total form fields in the Ezsigntemplate. | [optional] [default to undefined]
**bEzsigntemplateIncomplete** | **boolean** | Indicate the Ezsigntemplate is incomplete and cannot be used | [default to undefined]
**sEzsignfoldertypeNameX** | **string** | The name of the Ezsignfoldertype in the language of the requester | [optional] [default to undefined]
**eEzsigntemplateType** | [**FieldEEzsigntemplateType**](FieldEEzsigntemplateType.md) |  | [default to undefined]

## Example

```typescript
import { EzsigntemplateListElement } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: EzsigntemplateListElement = {
    pkiEzsigntemplateID,
    fkiEzsignfoldertypeID,
    fkiLanguageID,
    sEzsigntemplateDescription,
    iEzsigntemplatedocumentPagetotal,
    iEzsigntemplateSignaturetotal,
    iEzsigntemplateFormfieldtotal,
    bEzsigntemplateIncomplete,
    sEzsignfoldertypeNameX,
    eEzsigntemplateType,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
