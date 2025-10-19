# WebhookRegenerateApikeyV1Request

Request for POST /1/object/webhook/{pkiWebhookID}/regenerateApikey

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**bWebhookIssigned** | **boolean** | Whether the requests will be signed or not | [optional] [default to undefined]

## Example

```typescript
import { WebhookRegenerateApikeyV1Request } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: WebhookRegenerateApikeyV1Request = {
    bWebhookIssigned,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
