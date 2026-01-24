# EzsignbulksendGetEzsignsignaturesAutomaticV1ResponseMPayload

Payload for GET /1/object/ezsignbulksend/{pkiEzsignbulksendID}/getEzsignsignaturesAutomatic

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**a_eEzsignsignatureType** | [**Set&lt;FieldEEzsignsignatureType&gt;**](FieldEEzsignsignatureType.md) | All eEzsignsignatureType contained in the response | [default to undefined]
**a_objEzsignfolder** | [**Array&lt;CustomEzsignfolderEzsignsignaturesAutomaticResponse&gt;**](CustomEzsignfolderEzsignsignaturesAutomaticResponse.md) |  | [default to undefined]

## Example

```typescript
import { EzsignbulksendGetEzsignsignaturesAutomaticV1ResponseMPayload } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: EzsignbulksendGetEzsignsignaturesAutomaticV1ResponseMPayload = {
    a_eEzsignsignatureType,
    a_objEzsignfolder,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
