# EzsigntemplatedocumentResponseCompound

A Ezsigntemplatedocument Object

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**pkiEzsigntemplatedocumentID** | **number** | The unique ID of the Ezsigntemplatedocument | [default to undefined]
**fkiEzsigntemplateID** | **number** | The unique ID of the Ezsigntemplate | [default to undefined]
**sEzsigntemplatedocumentName** | **string** | The name of the Ezsigntemplatedocument. | [default to undefined]
**iEzsigntemplatedocumentPagetotal** | **number** | The number of pages in the Ezsigntemplatedocument. | [default to undefined]
**iEzsigntemplatedocumentSignaturetotal** | **number** | The number of total signatures in the Ezsigntemplate. | [default to undefined]
**iEzsigntemplatedocumentFormfieldtotal** | **number** | The number of total form fields in the Ezsigntemplate. | [default to undefined]
**bEzsigntemplatedocumentHassignedsignatures** | **boolean** | If the Ezsigntemplatedocument contains signed signatures (From internal or external sources) | [default to undefined]

## Example

```typescript
import { EzsigntemplatedocumentResponseCompound } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: EzsigntemplatedocumentResponseCompound = {
    pkiEzsigntemplatedocumentID,
    fkiEzsigntemplateID,
    sEzsigntemplatedocumentName,
    iEzsigntemplatedocumentPagetotal,
    iEzsigntemplatedocumentSignaturetotal,
    iEzsigntemplatedocumentFormfieldtotal,
    bEzsigntemplatedocumentHassignedsignatures,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
