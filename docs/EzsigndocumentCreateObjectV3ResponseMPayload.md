# EzsigndocumentCreateObjectV3ResponseMPayload

Payload for POST /3/object/ezsigndocument

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**a_objEzsigndocument** | [**Array&lt;EzsigndocumentCreateElementV3Response&gt;**](EzsigndocumentCreateElementV3Response.md) | An array of objets that contain unique IDs representing the object that were requested to be created and possibly matching template IDs.  They are returned in the same order as the array containing the objects to be created that was sent in the request. | [default to undefined]

## Example

```typescript
import { EzsigndocumentCreateObjectV3ResponseMPayload } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: EzsigndocumentCreateObjectV3ResponseMPayload = {
    a_objEzsigndocument,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
