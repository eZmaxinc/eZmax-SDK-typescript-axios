# EzsigndocumentApplyEzsigntemplateV2Request

Request for POST /2/object/ezsigndocument/{pkiEzsigndocumentID}/applyezsigntemplate

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**fkiEzsigntemplateID** | **number** | The unique ID of the Ezsigntemplate | [default to undefined]
**a_sEzsigntemplatesigner** | **Array&lt;string&gt;** |  | [default to undefined]
**a_pkiEzsignfoldersignerassociationID** | **Array&lt;number&gt;** |  | [default to undefined]

## Example

```typescript
import { EzsigndocumentApplyEzsigntemplateV2Request } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: EzsigndocumentApplyEzsigntemplateV2Request = {
    fkiEzsigntemplateID,
    a_sEzsigntemplatesigner,
    a_pkiEzsignfoldersignerassociationID,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
