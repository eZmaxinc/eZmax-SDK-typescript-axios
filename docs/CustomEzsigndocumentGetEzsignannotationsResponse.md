# CustomEzsigndocumentGetEzsignannotationsResponse

An Ezsigndocument Object in the context of a getEzsignannotations path

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**pkiEzsigndocumentID** | **number** | The unique ID of the Ezsigndocument | [default to undefined]
**sEzsigndocumentName** | **string** | The name of the document that will be presented to Ezsignfoldersignerassociations | [default to undefined]
**a_objEzsignannotation** | [**Array&lt;EzsignannotationResponseCompound&gt;**](EzsignannotationResponseCompound.md) |  | [default to undefined]

## Example

```typescript
import { CustomEzsigndocumentGetEzsignannotationsResponse } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: CustomEzsigndocumentGetEzsignannotationsResponse = {
    pkiEzsigndocumentID,
    sEzsigndocumentName,
    a_objEzsignannotation,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
