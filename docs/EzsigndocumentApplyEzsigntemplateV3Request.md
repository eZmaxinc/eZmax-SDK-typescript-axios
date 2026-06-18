# EzsigndocumentApplyEzsigntemplateV3Request

Request for POST /3/object/ezsigndocument/{pkiEzsigndocumentID}/applyezsigntemplate

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**fkiEzsigntemplateID** | **number** | The unique ID of the Ezsigntemplate | [default to undefined]
**a_sEzsigntemplatesigner** | **Array&lt;string&gt;** |  | [default to undefined]
**a_fkiEzsignfoldersignerassociationID** | **Array&lt;number&gt;** |  | [default to undefined]
**a_sEzsigntemplateannotationDescription** | **Set&lt;string&gt;** |  | [default to undefined]
**a_sEzsigntemplateannotationDefaulttext** | **Array&lt;string&gt;** |  | [default to undefined]

## Example

```typescript
import { EzsigndocumentApplyEzsigntemplateV3Request } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: EzsigndocumentApplyEzsigntemplateV3Request = {
    fkiEzsigntemplateID,
    a_sEzsigntemplatesigner,
    a_fkiEzsignfoldersignerassociationID,
    a_sEzsigntemplateannotationDescription,
    a_sEzsigntemplateannotationDefaulttext,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
