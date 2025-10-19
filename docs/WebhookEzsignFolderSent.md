# WebhookEzsignFolderSent

This is the base Webhook object

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**objWebhook** | [**CustomWebhookResponse**](CustomWebhookResponse.md) |  | [default to undefined]
**a_objAttempt** | [**Array&lt;AttemptResponseCompound&gt;**](AttemptResponseCompound.md) | An array containing details of previous attempts that were made to deliver the message. The array is empty if it\&#39;s the first attempt. | [default to undefined]
**objEzsignfolder** | [**EzsignfolderResponse**](EzsignfolderResponse.md) |  | [default to undefined]

## Example

```typescript
import { WebhookEzsignFolderSent } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: WebhookEzsignFolderSent = {
    objWebhook,
    a_objAttempt,
    objEzsignfolder,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
