# EzsigndocumentGetEzsignsignaturesAutomaticV1ResponseMPayload

Payload for GET /1/object/ezsigndocument/{pkiEzsigndocumentID}/getEzsignsignaturesAutomatic

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**a_eEzsignsignatureType** | [**Set&lt;FieldEEzsignsignatureType&gt;**](FieldEEzsignsignatureType.md) | All eEzsignsignatureType contained in the response | [default to undefined]
**a_objEzsignfolder** | [**Array&lt;CustomEzsignfolderEzsignsignaturesAutomaticResponse&gt;**](CustomEzsignfolderEzsignsignaturesAutomaticResponse.md) |  | [default to undefined]

## Example

```typescript
import { EzsigndocumentGetEzsignsignaturesAutomaticV1ResponseMPayload } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: EzsigndocumentGetEzsignsignaturesAutomaticV1ResponseMPayload = {
    a_eEzsignsignatureType,
    a_objEzsignfolder,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
