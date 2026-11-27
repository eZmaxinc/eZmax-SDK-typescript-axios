# AttachmentRenameV1Request

Request for POST /1/object/attachment/{pkiAttachmentID}/rename

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**sAttachmentName** | **string** | The name of the Attachment | [default to undefined]
**sAttachmentCategory** | **string** | The attachment category | [default to undefined]
**bForceOverride** | **boolean** | Forces an override if the attachment name and category conflicts with another attachment. | [optional] [default to undefined]

## Example

```typescript
import { AttachmentRenameV1Request } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: AttachmentRenameV1Request = {
    sAttachmentName,
    sAttachmentCategory,
    bForceOverride,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
