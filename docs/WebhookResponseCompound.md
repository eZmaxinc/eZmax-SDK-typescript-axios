# WebhookResponseCompound

A Webhook Object

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**pkiWebhookID** | **number** | The unique ID of the Webhook | [default to undefined]
**fkiAuthenticationexternalID** | **number** | The unique ID of the Authenticationexternal | [optional] [default to undefined]
**sWebhookDescription** | **string** | The description of the Webhook | [default to undefined]
**fkiEzsignfoldertypeID** | **number** | The unique ID of the Ezsignfoldertype. | [optional] [default to undefined]
**sEzsignfoldertypeNameX** | **string** | The name of the Ezsignfoldertype in the language of the requester | [optional] [default to undefined]
**eWebhookModule** | [**FieldEWebhookModule**](FieldEWebhookModule.md) |  | [default to undefined]
**eWebhookEzsignevent** | [**FieldEWebhookEzsignevent**](FieldEWebhookEzsignevent.md) |  | [optional] [default to undefined]
**eWebhookManagementevent** | [**FieldEWebhookManagementevent**](FieldEWebhookManagementevent.md) |  | [optional] [default to undefined]
**sWebhookUrl** | **string** | The URL of the Webhook callback | [default to undefined]
**sWebhookEmailfailed** | **string** | The email that will receive the Webhook in case all attempts fail | [default to undefined]
**sWebhookApikey** | **string** | The Apikey for the Webhook.  This will be hidden if we are not creating or regenerating the Apikey. | [optional] [default to undefined]
**sWebhookSecret** | **string** | The Secret for the Webhook.  This will be hidden if we are not creating or regenerating the Apikey. | [optional] [default to undefined]
**bWebhookIsactive** | **boolean** | Whether the Webhook is active or not | [default to undefined]
**bWebhookIssigned** | **boolean** | Whether the requests will be signed or not | [default to undefined]
**bWebhookSkipsslvalidation** | **boolean** | Wheter the server\&#39;s SSL certificate should be validated or not. Not recommended to skip for production use | [default to undefined]
**sAuthenticationexternalDescription** | **string** | The description of the Authenticationexternal | [optional] [default to undefined]
**objAudit** | [**CommonAudit**](CommonAudit.md) |  | [default to undefined]
**sWebhookEvent** | **string** | The concatenated string to describe the Webhook event | [optional] [default to undefined]
**sWebhookAuthentificationexternalerror** | **string** | Error message when token renewal failed or is not configured. Only if an Authenticationexternal is set. | [optional] [default to undefined]
**a_objWebhookheader** | [**Array&lt;WebhookheaderResponseCompound&gt;**](WebhookheaderResponseCompound.md) |  | [optional] [default to undefined]

## Example

```typescript
import { WebhookResponseCompound } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: WebhookResponseCompound = {
    pkiWebhookID,
    fkiAuthenticationexternalID,
    sWebhookDescription,
    fkiEzsignfoldertypeID,
    sEzsignfoldertypeNameX,
    eWebhookModule,
    eWebhookEzsignevent,
    eWebhookManagementevent,
    sWebhookUrl,
    sWebhookEmailfailed,
    sWebhookApikey,
    sWebhookSecret,
    bWebhookIsactive,
    bWebhookIssigned,
    bWebhookSkipsslvalidation,
    sAuthenticationexternalDescription,
    objAudit,
    sWebhookEvent,
    sWebhookAuthentificationexternalerror,
    a_objWebhookheader,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
