# EzsigndocumentGetDownloadUrlV1ResponseMPayload

Payload for GET /1/object/ezsigndocument/{pkiEzsigndocument}/getDownloadUrl

## Properties

Name | Type | Description | Notes
------------ | ------------- | ------------- | -------------
**sDownloadUrl** | **string** | The Url to the requested document.  Url will expire after 5 minutes. | [default to undefined]

## Example

```typescript
import { EzsigndocumentGetDownloadUrlV1ResponseMPayload } from '@ezmaxinc/ezmax-sdk-typescript-axios';

const instance: EzsigndocumentGetDownloadUrlV1ResponseMPayload = {
    sDownloadUrl,
};
```

[[Back to Model list]](../README.md#documentation-for-models) [[Back to API list]](../README.md#documentation-for-api-endpoints) [[Back to README]](../README.md)
