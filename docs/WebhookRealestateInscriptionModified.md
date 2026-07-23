# WebhookRealestateInscriptionModified

This is a webhook for a RealestateInscriptionModified event

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**objWebhook** | [**CustomWebhookResponse**](CustomWebhookResponse.md) |  | [default to undefined]
**a_objAttempt** | [**Array&lt;AttemptResponseCompound&gt;**](AttemptResponseCompound.md) | An array containing details of previous attempts that were made to deliver the message. The array is empty if it\&#39;s the first attempt. | [default to undefined]
**objInscription** | [**InscriptionResponse**](InscriptionResponse.md) |  | [default to undefined]

## Example

```typescript
import { WebhookRealestateInscriptionModified } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: WebhookRealestateInscriptionModified = {
    objWebhook,
    a_objAttempt,
    objInscription,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
