# WebhookSendWebhookV1Request

Request for POST /1/object/webhook/sendWebhook

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**eWebhookModule** | [**FieldEWebhookModule**](FieldEWebhookModule.md) |  | [default to undefined]
**eWebhookEzsignevent** | [**CustomEWebhookEzsignevent**](CustomEWebhookEzsignevent.md) |  | [optional] [default to undefined]
**eWebhookManagementevent** | [**FieldEWebhookManagementevent**](FieldEWebhookManagementevent.md) |  | [optional] [default to undefined]
**fkiEzsignfolderID** | **number** | The unique ID of the Ezsignfolder | [optional] [default to undefined]
**fkiEzsigndocumentID** | **number** | The unique ID of the Ezsigndocument | [optional] [default to undefined]
**fkiEzsignsignerID** | **number** | The unique ID of the Ezsignsigner | [optional] [default to undefined]
**fkiUserID** | **number** | The unique ID of the User | [optional] [default to undefined]
**fkiUserstagedID** | **number** | The unique ID of the Userstaged | [optional] [default to undefined]

## Example

```typescript
import { WebhookSendWebhookV1Request } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: WebhookSendWebhookV1Request = {
    eWebhookModule,
    eWebhookEzsignevent,
    eWebhookManagementevent,
    fkiEzsignfolderID,
    fkiEzsigndocumentID,
    fkiEzsignsignerID,
    fkiUserID,
    fkiUserstagedID,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
