# WebhookCreateObjectV2Response

Response for POST /2/object/webhook

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**objDebugPayload** | [**CommonResponseObjDebugPayload**](CommonResponseObjDebugPayload.md) |  | [default to undefined]
**objDebug** | [**CommonResponseObjDebug**](CommonResponseObjDebug.md) |  | [optional] [default to undefined]
**mPayload** | [**WebhookCreateObjectV2ResponseMPayload**](WebhookCreateObjectV2ResponseMPayload.md) |  | [default to undefined]

## Example

```typescript
import { WebhookCreateObjectV2Response } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: WebhookCreateObjectV2Response = {
    objDebugPayload,
    objDebug,
    mPayload,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
