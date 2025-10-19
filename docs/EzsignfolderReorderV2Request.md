# EzsignfolderReorderV2Request

Request for POST /2/object/ezsignfolder/{pkiEzsignfolderID}/reorder

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**eEzsignfolderDocumentdependency** | [**FieldEEzsignfolderDocumentdependency**](FieldEEzsignfolderDocumentdependency.md) |  | [optional] [default to undefined]
**a_objEzsigndocument** | [**Array&lt;CustomEzsigndocumentRequest&gt;**](CustomEzsigndocumentRequest.md) |  | [default to undefined]

## Example

```typescript
import { EzsignfolderReorderV2Request } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: EzsignfolderReorderV2Request = {
    eEzsignfolderDocumentdependency,
    a_objEzsigndocument,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
