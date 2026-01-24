# CustomAttachmentImportIntoEDMResponse

A AttachmentImportIntoEDM object

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**pkiAttachmentIDSource** | **number** | The unique ID of the Attachment. | [optional] [default to undefined]
**pkiAttachmentIDNew** | **number** | The unique ID of the Attachment. | [optional] [default to undefined]
**eAttachmentStatus** | **string** |  | [optional] [default to undefined]
**bAllowOverwrite** | **boolean** | Whether we allow or not the file overwrite | [optional] [default to undefined]

## Example

```typescript
import { CustomAttachmentImportIntoEDMResponse } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: CustomAttachmentImportIntoEDMResponse = {
    pkiAttachmentIDSource,
    pkiAttachmentIDNew,
    eAttachmentStatus,
    bAllowOverwrite,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
