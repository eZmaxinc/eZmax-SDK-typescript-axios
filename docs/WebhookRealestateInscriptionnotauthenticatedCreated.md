# WebhookRealestateInscriptionnotauthenticatedCreated

This is a webhook for a RealestateInscriptionnotauthenticatedCreated event

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**objWebhook** | [**CustomWebhookResponse**](CustomWebhookResponse.md) |  | [default to undefined]
**a_objAttempt** | [**Array&lt;AttemptResponseCompound&gt;**](AttemptResponseCompound.md) | An array containing details of previous attempts that were made to deliver the message. The array is empty if it\&#39;s the first attempt. | [default to undefined]
**objInscriptionnotauthenticated** | [**InscriptionnotauthenticatedResponse**](InscriptionnotauthenticatedResponse.md) |  | [default to undefined]

## Example

```typescript
import { WebhookRealestateInscriptionnotauthenticatedCreated } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: WebhookRealestateInscriptionnotauthenticatedCreated = {
    objWebhook,
    a_objAttempt,
    objInscriptionnotauthenticated,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
