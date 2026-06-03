# CustomEzsigndocumentGetEzsignsignaturesResponse

An Ezsigndocument Object in the context of a getEzsignsignatures path

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**pkiEzsigndocumentID** | **number** | The unique ID of the Ezsigndocument | [default to undefined]
**sEzsigndocumentName** | **string** | The name of the document that will be presented to Ezsignfoldersignerassociations | [default to undefined]
**a_objEzsignsignature** | [**Array&lt;EzsignsignatureResponseCompound&gt;**](EzsignsignatureResponseCompound.md) |  | [default to undefined]

## Example

```typescript
import { CustomEzsigndocumentGetEzsignsignaturesResponse } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: CustomEzsigndocumentGetEzsignsignaturesResponse = {
    pkiEzsigndocumentID,
    sEzsigndocumentName,
    a_objEzsignsignature,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
