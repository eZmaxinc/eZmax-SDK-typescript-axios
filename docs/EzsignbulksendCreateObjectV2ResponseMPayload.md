# EzsignbulksendCreateObjectV2ResponseMPayload

Payload for POST /2/object/ezsignbulksend

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**a_pkiEzsignbulksendID** | **Array&lt;number&gt;** | An array of unique IDs representing the object that were requested to be created.  They are returned in the same order as the array containing the objects to be created that was sent in the request. | [default to undefined]

## Example

```typescript
import { EzsignbulksendCreateObjectV2ResponseMPayload } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: EzsignbulksendCreateObjectV2ResponseMPayload = {
    a_pkiEzsignbulksendID,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
