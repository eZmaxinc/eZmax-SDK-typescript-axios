# WebhookEzmaxpartnerproductSubscribe

This is the base Webhook object

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**objWebhook** | [**CustomWebhookResponse**](CustomWebhookResponse.md) |  | [default to undefined]
**a_objAttempt** | [**Array&lt;AttemptResponseCompound&gt;**](AttemptResponseCompound.md) | An array containing details of previous attempts that were made to deliver the message. The array is empty if it\&#39;s the first attempt. | [default to undefined]
**objEzmaxpartnerproduct** | [**CustomEzmaxpartnerproductSubscribe**](CustomEzmaxpartnerproductSubscribe.md) |  | [default to undefined]
**sExternalID** | **string** |  | [optional] [default to undefined]
**sApikeyApikey** | **string** |  | [optional] [default to undefined]
**sApikeySecret** | **string** |  | [optional] [default to undefined]

## Example

```typescript
import { WebhookEzmaxpartnerproductSubscribe } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: WebhookEzmaxpartnerproductSubscribe = {
    objWebhook,
    a_objAttempt,
    objEzmaxpartnerproduct,
    sExternalID,
    sApikeyApikey,
    sApikeySecret,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
