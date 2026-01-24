# EzsigndocumentApplyEzsigntemplateglobalV1Request

Request for POST /1/object/ezsigndocument/{pkiEzsigndocumentID}/applyEzsigntemplateglobal

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**fkiEzsigntemplateglobalID** | **number** | The unique ID of the Ezsigntemplateglobal | [default to undefined]
**a_sEzsigntemplateglobalsigner** | **Array&lt;string&gt;** |  | [default to undefined]
**a_pkiEzsignfoldersignerassociationID** | **Array&lt;number&gt;** |  | [default to undefined]

## Example

```typescript
import { EzsigndocumentApplyEzsigntemplateglobalV1Request } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: EzsigndocumentApplyEzsigntemplateglobalV1Request = {
    fkiEzsigntemplateglobalID,
    a_sEzsigntemplateglobalsigner,
    a_pkiEzsignfoldersignerassociationID,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
