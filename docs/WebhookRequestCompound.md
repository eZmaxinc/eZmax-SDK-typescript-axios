# WebhookRequestCompound

A Webhook Object and children

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**pkiWebhookID** | **number** | The unique ID of the Webhook | [optional] [default to undefined]
**fkiAuthenticationexternalID** | **number** | The unique ID of the Authenticationexternal | [optional] [default to undefined]
**fkiEzsignfoldertypeID** | **number** | The unique ID of the Ezsignfoldertype. | [optional] [default to undefined]
**sWebhookDescription** | **string** | The description of the Webhook | [default to undefined]
**eWebhookModule** | [**FieldEWebhookModule**](FieldEWebhookModule.md) |  | [default to undefined]
**eWebhookEzsignevent** | [**FieldEWebhookEzsignevent**](FieldEWebhookEzsignevent.md) |  | [optional] [default to undefined]
**eWebhookManagementevent** | [**FieldEWebhookManagementevent**](FieldEWebhookManagementevent.md) |  | [optional] [default to undefined]
**sWebhookUrl** | **string** | The URL of the Webhook callback | [default to undefined]
**sWebhookEmailfailed** | **string** | The email that will receive the Webhook in case all attempts fail | [default to undefined]
**bWebhookIsactive** | **boolean** | Whether the Webhook is active or not | [default to undefined]
**bWebhookIssigned** | **boolean** | Whether the requests will be signed or not | [optional] [default to undefined]
**bWebhookSkipsslvalidation** | **boolean** | Wheter the server\&#39;s SSL certificate should be validated or not. Not recommended to skip for production use | [default to undefined]
**a_objWebhookheader** | [**Array&lt;WebhookheaderRequestCompound&gt;**](WebhookheaderRequestCompound.md) |  | [optional] [default to undefined]

## Example

```typescript
import { WebhookRequestCompound } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: WebhookRequestCompound = {
    pkiWebhookID,
    fkiAuthenticationexternalID,
    fkiEzsignfoldertypeID,
    sWebhookDescription,
    eWebhookModule,
    eWebhookEzsignevent,
    eWebhookManagementevent,
    sWebhookUrl,
    sWebhookEmailfailed,
    bWebhookIsactive,
    bWebhookIssigned,
    bWebhookSkipsslvalidation,
    a_objWebhookheader,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
