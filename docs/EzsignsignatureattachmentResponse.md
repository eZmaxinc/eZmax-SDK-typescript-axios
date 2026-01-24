# EzsignsignatureattachmentResponse

An Ezsignsignatureattachment Object

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**pkiEzsignsignatureattachmentID** | **number** | The unique ID of the Ezsignsignatureattachment | [default to undefined]
**fkiEzsignsignatureID** | **number** | The unique ID of the Ezsignsignature | [default to undefined]
**binEzsignsignatureattachmentMD5** | **string** | The md5 of the Ezsignsignatureattachment | [default to undefined]
**sEzsignsignatureattachmentName** | **string** | The name of the Ezsignsignatureattachment | [default to undefined]
**sDownloadUrl** | **string** | The Url to the requested document.  Url will expire after 3 hours. | [default to undefined]

## Example

```typescript
import { EzsignsignatureattachmentResponse } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: EzsignsignatureattachmentResponse = {
    pkiEzsignsignatureattachmentID,
    fkiEzsignsignatureID,
    binEzsignsignatureattachmentMD5,
    sEzsignsignatureattachmentName,
    sDownloadUrl,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
