# DomainCreateObjectV1ResponseMPayload

Payload for POST /1/object/domain

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**a_pkiDomainID** | **Array&lt;number&gt;** | An array of unique IDs representing the object that were requested to be created.  They are returned in the same order as the array containing the objects to be created that was sent in the request. | [default to undefined]

## Example

```typescript
import { DomainCreateObjectV1ResponseMPayload } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: DomainCreateObjectV1ResponseMPayload = {
    a_pkiDomainID,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
