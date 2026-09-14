# AttachmentRestoreV1Request

Request for POST /1/object/attachment/{pkiAttachmentID}/restore

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**bForceOverride** | **boolean** | Forces an override if the attachment name and category conflicts with another attachment. | [optional] [default to undefined]

## Example

```typescript
import { AttachmentRestoreV1Request } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: AttachmentRestoreV1Request = {
    bForceOverride,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
