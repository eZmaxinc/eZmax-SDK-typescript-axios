# AttachmentlogResponseCompound

A Attachmentlog Object

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**fkiAttachmentID** | **number** | The unique ID of the Attachment. | [default to undefined]
**fkiUserID** | **number** | The unique ID of the User | [default to undefined]
**dtAttachmentlogDatetime** | **string** | The created date | [default to undefined]
**eAttachmentlogType** | [**FieldEAttachmentlogType**](FieldEAttachmentlogType.md) |  | [default to undefined]
**sAttachmentlogDetail** | **string** | The additionnal detail | [optional] [default to undefined]

## Example

```typescript
import { AttachmentlogResponseCompound } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: AttachmentlogResponseCompound = {
    fkiAttachmentID,
    fkiUserID,
    dtAttachmentlogDatetime,
    eAttachmentlogType,
    sAttachmentlogDetail,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
