# AttachmentValidateV1Request

Request for POST /1/object/attachment/{pkiAttachmentID}/validate

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**fkiAttachmentrejectreasonID** | **number** | The unique ID of the Attachmentrejectreason | [optional] [default to undefined]
**eAttachmentVerified** | [**FieldEAttachmentVerified**](FieldEAttachmentVerified.md) |  | [default to undefined]
**tAttachmentRejectioncomment** | **string** | The rejectioncomment of the Attachment | [optional] [default to undefined]
**a_sNotificationEmailAddress** | **Set&lt;string&gt;** | A list of email addresses to send a rejection notification to. | [optional] [default to undefined]
**tNotificationMessage** | **string** | The email body to send to the notification recipients. | [optional] [default to undefined]
**bNotificationIncludeAttachment** | **boolean** | Should a copy of the attachment be included in the email. | [optional] [default to undefined]

## Example

```typescript
import { AttachmentValidateV1Request } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: AttachmentValidateV1Request = {
    fkiAttachmentrejectreasonID,
    eAttachmentVerified,
    tAttachmentRejectioncomment,
    a_sNotificationEmailAddress,
    tNotificationMessage,
    bNotificationIncludeAttachment,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
