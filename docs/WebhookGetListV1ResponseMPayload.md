# WebhookGetListV1ResponseMPayload

Payload for GET /1/object/webhook/getList

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**iRowReturned** | **number** | The number of rows returned | [default to undefined]
**iRowFiltered** | **number** | The number of rows matching your filters (if any) or the total number of rows | [default to undefined]
**a_objWebhook** | [**Array&lt;WebhookListElement&gt;**](WebhookListElement.md) |  | [default to undefined]

## Example

```typescript
import { WebhookGetListV1ResponseMPayload } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: WebhookGetListV1ResponseMPayload = {
    iRowReturned,
    iRowFiltered,
    a_objWebhook,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
