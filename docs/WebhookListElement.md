# WebhookListElement

A Webhook List Element

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**pkiWebhookID** | **number** | The unique ID of the Webhook | [default to undefined]
**sWebhookDescription** | **string** | The description of the Webhook | [default to undefined]
**sWebhookUrl** | **string** | The URL of the Webhook callback | [default to undefined]
**sWebhookEvent** | **string** | The concatenated string to describe the Webhook event | [default to undefined]
**sWebhookEmailfailed** | **string** | The email that will receive the Webhook in case all attempts fail | [default to undefined]
**eWebhookModule** | [**FieldEWebhookModule**](FieldEWebhookModule.md) |  | [default to undefined]
**eWebhookEzsignevent** | [**FieldEWebhookEzsignevent**](FieldEWebhookEzsignevent.md) |  | [optional] [default to undefined]
**eWebhookManagementevent** | [**FieldEWebhookManagementevent**](FieldEWebhookManagementevent.md) |  | [optional] [default to undefined]
**eWebhookRealestateevent** | [**FieldEWebhookRealestateevent**](FieldEWebhookRealestateevent.md) |  | [optional] [default to undefined]
**bWebhookIsactive** | **boolean** | Whether the Webhook is active or not | [default to undefined]
**bWebhookIssigned** | **boolean** | Whether the requests will be signed or not | [default to undefined]

## Example

```typescript
import { WebhookListElement } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: WebhookListElement = {
    pkiWebhookID,
    sWebhookDescription,
    sWebhookUrl,
    sWebhookEvent,
    sWebhookEmailfailed,
    eWebhookModule,
    eWebhookEzsignevent,
    eWebhookManagementevent,
    eWebhookRealestateevent,
    bWebhookIsactive,
    bWebhookIssigned,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
