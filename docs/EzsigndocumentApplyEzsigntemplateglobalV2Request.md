# EzsigndocumentApplyEzsigntemplateglobalV2Request

Request for POST /2/object/ezsigndocument/{pkiEzsigndocumentID}/applyEzsigntemplateglobal

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**fkiEzsigntemplateglobalID** | **number** | The unique ID of the Ezsigntemplateglobal | [default to undefined]
**a_sEzsigntemplateglobalsigner** | **Array&lt;string&gt;** |  | [default to undefined]
**a_fkiEzsignfoldersignerassociationID** | **Array&lt;number&gt;** |  | [default to undefined]
**a_sEzsigntemplateglobalannotationDescription** | **Array&lt;string&gt;** |  | [optional] [default to undefined]
**a_sEzsigntemplateglobalannotationDefaulttext** | **Array&lt;string&gt;** |  | [optional] [default to undefined]

## Example

```typescript
import { EzsigndocumentApplyEzsigntemplateglobalV2Request } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: EzsigndocumentApplyEzsigntemplateglobalV2Request = {
    fkiEzsigntemplateglobalID,
    a_sEzsigntemplateglobalsigner,
    a_fkiEzsignfoldersignerassociationID,
    a_sEzsigntemplateglobalannotationDescription,
    a_sEzsigntemplateglobalannotationDefaulttext,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
