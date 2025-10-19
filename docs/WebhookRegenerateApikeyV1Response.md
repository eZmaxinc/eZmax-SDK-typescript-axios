# WebhookRegenerateApikeyV1Response

Response for POST /1/object/webhook/{pkiWebhookID}/regenerateApikey

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**objDebugPayload** | [**CommonResponseObjDebugPayload**](CommonResponseObjDebugPayload.md) |  | [default to undefined]
**objDebug** | [**CommonResponseObjDebug**](CommonResponseObjDebug.md) |  | [optional] [default to undefined]
**mPayload** | [**WebhookRegenerateApikeyV1ResponseMPayload**](WebhookRegenerateApikeyV1ResponseMPayload.md) |  | [default to undefined]

## Example

```typescript
import { WebhookRegenerateApikeyV1Response } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: WebhookRegenerateApikeyV1Response = {
    objDebugPayload,
    objDebug,
    mPayload,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
